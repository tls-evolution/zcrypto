// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/zmap/zcrypto/x509"
)

type clientHandshakeState struct {
	c               *Conn
	serverHello     *serverHelloMsg
	serverHello13   *serverHelloMsg13
	hello           *clientHelloMsg
	suite           *cipherSuite
	finishedHash    finishedHash
	masterSecret    []byte
	preMasterSecret []byte
	session         *ClientSessionState
}

type CacheKeyGenerator interface {
	Key(net.Addr) string
}

type ClientFingerprintConfiguration struct {
	// Version in the handshake header
	HandshakeVersion uint16

	// if len == 32, it will specify the client random.
	// Otherwise, the field will be random
	// except the top 4 bytes if InsertTimestamp is true
	ClientRandom    []byte
	InsertTimestamp bool

	// if RandomSessionID > 0, will overwrite SessionID w/ that many
	// random bytes when a session resumption occurs
	RandomSessionID int
	SessionID       []byte

	// These fields will appear exactly in order in the ClientHello
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []ClientExtension

	// Optional, both must be non-nil, or neither.
	// Custom Session cache implementations allowed
	SessionCache ClientSessionCache
	CacheKey     CacheKeyGenerator
}

type ClientExtension interface {
	// Produce the bytes on the wire for this extension, type and length included
	Marshal() []byte

	// Function will return an error if zTLS does not implement the necessary features for this extension
	CheckImplemented() error

	// Modifies the config to reflect the state of the extension
	WriteToConfig(*Config) error
}

func (c *ClientFingerprintConfiguration) CheckImplementedExtensions() error {
	for _, ext := range c.Extensions {
		if err := ext.CheckImplemented(); err != nil {
			return err
		}
	}
	return nil
}

func (c *clientHelloMsg) WriteToConfig(config *Config) error {
	config.NextProtos = c.alpnProtocols
	config.CipherSuites = c.cipherSuites
	config.MaxVersion = c.vers
	config.ClientRandom = c.random
	config.CurvePreferences = c.supportedCurves
	config.HeartbeatEnabled = c.heartbeatEnabled
	config.ExtendedRandom = c.extendedRandomEnabled
	config.ForceSessionTicketExt = c.ticketSupported
	config.ExtendedMasterSecret = c.extendedMasterSecret
	config.SignedCertificateTimestampExt = c.sctEnabled
	return nil
}

func (c *ClientFingerprintConfiguration) WriteToConfig(config *Config) error {
	config.NextProtos = []string{}
	config.CipherSuites = c.CipherSuites
	config.MaxVersion = c.HandshakeVersion
	config.ClientRandom = c.ClientRandom
	config.CurvePreferences = []CurveID{}
	config.HeartbeatEnabled = false
	config.ExtendedRandom = false
	config.ForceSessionTicketExt = false
	config.ExtendedMasterSecret = false
	config.SignedCertificateTimestampExt = false
	for _, ext := range c.Extensions {
		if err := ext.WriteToConfig(config); err != nil {
			return err
		}
	}
	return nil
}

func currentTimestamp() ([]byte, error) {
	t := time.Now().Unix()
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, t)
	return buf.Bytes(), err
}

func (c *ClientFingerprintConfiguration) marshal(config *Config) ([]byte, error) {
	if err := c.CheckImplementedExtensions(); err != nil {
		return nil, err
	}
	head := make([]byte, 38)
	head[0] = 1
	head[4] = uint8(c.HandshakeVersion >> 8)
	head[5] = uint8(c.HandshakeVersion)
	if len(c.ClientRandom) == 32 {
		copy(head[6:38], c.ClientRandom[0:32])
	} else {
		start := 6
		if c.InsertTimestamp {
			t, err := currentTimestamp()
			if err != nil {
				return nil, err
			}
			copy(head[start:start+4], t)
			start = start + 4
		}
		_, err := io.ReadFull(config.rand(), head[start:38])
		if err != nil {
			return nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if len(c.SessionID) >= 256 {
		return nil, errors.New("tls: SessionID too long")
	}
	sessionID := make([]byte, len(c.SessionID)+1)
	sessionID[0] = uint8(len(c.SessionID))
	if len(c.SessionID) > 0 {
		copy(sessionID[1:], c.SessionID)
	}

	ciphers := make([]byte, 2+2*len(c.CipherSuites))
	ciphers[0] = uint8(len(c.CipherSuites) >> 7)
	ciphers[1] = uint8(len(c.CipherSuites) << 1)
	for i, suite := range c.CipherSuites {
		if !config.ForceSuites {
			found := false
			for _, impl := range implementedCipherSuites {
				if impl.id == suite {
					found = true
				}
			}
			if !found {
				return nil, errors.New(fmt.Sprintf("tls: unimplemented cipher suite %d", suite))
			}
		}

		ciphers[2+i*2] = uint8(suite >> 8)
		ciphers[3+i*2] = uint8(suite)
	}

	if len(c.CompressionMethods) >= 256 {
		return nil, errors.New("tls: Too many compression methods")
	}
	compressions := make([]byte, len(c.CompressionMethods)+1)
	compressions[0] = uint8(len(c.CompressionMethods))
	if len(c.CompressionMethods) > 0 {
		copy(compressions[1:], c.CompressionMethods)
		if c.CompressionMethods[0] != 0 {
			return nil, errors.New(fmt.Sprintf("tls: unimplemented compression method %d", c.CompressionMethods[0]))
		}
		if len(c.CompressionMethods) > 1 {
			return nil, errors.New(fmt.Sprintf("tls: unimplemented compression method %d", c.CompressionMethods[1]))
		}
	} else {
		return nil, errors.New("tls: no compression method")
	}

	var extensions []byte
	for _, ext := range c.Extensions {
		extensions = append(extensions, ext.Marshal()...)
	}
	if len(extensions) > 0 {
		length := make([]byte, 2)
		length[0] = uint8(len(extensions) >> 8)
		length[1] = uint8(len(extensions))
		extensions = append(length, extensions...)
	}
	helloArray := [][]byte{head, sessionID, ciphers, compressions, extensions}
	hello := []byte{}
	for _, b := range helloArray {
		hello = append(hello, b...)
	}
	lengthOnTheWire := len(hello) - 4
	if lengthOnTheWire >= 1<<24 {
		return nil, errors.New("ClientHello message too long")
	}
	hello[1] = uint8(lengthOnTheWire >> 16)
	hello[2] = uint8(lengthOnTheWire >> 8)
	hello[3] = uint8(lengthOnTheWire)

	return hello, nil
}

func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}
	var hello *clientHelloMsg
	var helloBytes []byte
	var session *ClientSessionState
	var sessionCache ClientSessionCache
	var cacheKey string

	// first, let's check if a ClientFingerprintConfiguration template was provided by the config
	if c.config.ClientFingerprintConfiguration != nil {
		if err := c.config.ClientFingerprintConfiguration.WriteToConfig(c.config); err != nil {
			return err
		}
		session = nil
		sessionCache = c.config.ClientFingerprintConfiguration.SessionCache
		if sessionCache != nil {
			if c.config.ClientFingerprintConfiguration.CacheKey == nil {
				return errors.New("tls: must specify CacheKey if SessionCache is defined in Config.ClientFingerprintConfiguration")
			}
			cacheKey = c.config.ClientFingerprintConfiguration.CacheKey.Key(c.conn.RemoteAddr())
			candidateSession, ok := sessionCache.Get(cacheKey)
			if ok {
				cipherSuiteOk := false
				for _, id := range c.config.ClientFingerprintConfiguration.CipherSuites {
					if id == candidateSession.cipherSuite {
						cipherSuiteOk = true
						break
					}
				}
				versOk := candidateSession.vers >= c.config.minVersion() &&
					candidateSession.vers <= c.config.ClientFingerprintConfiguration.HandshakeVersion
				if versOk && cipherSuiteOk {
					session = candidateSession
				}
			}
		}
		for i, ext := range c.config.ClientFingerprintConfiguration.Extensions {
			switch casted := ext.(type) {
			case *SessionTicketExtension:
				if casted.Autopopulate {
					if session == nil {
						if !c.config.ForceSessionTicketExt {
							c.config.ClientFingerprintConfiguration.Extensions[i] = &NullExtension{}
						}
					} else {
						c.config.ClientFingerprintConfiguration.Extensions[i] = &SessionTicketExtension{session.sessionTicket, true}
						if c.config.ClientFingerprintConfiguration.RandomSessionID > 0 {
							c.config.ClientFingerprintConfiguration.SessionID = make([]byte, c.config.ClientFingerprintConfiguration.RandomSessionID)
							if _, err := io.ReadFull(c.config.rand(), c.config.ClientFingerprintConfiguration.SessionID); err != nil {
								c.sendAlert(alertInternalError)
								return errors.New("tls: short read from Rand: " + err.Error())
							}

						}
					}
				}
			}
		}
		var err error
		helloBytes, err = c.config.ClientFingerprintConfiguration.marshal(c.config)
		if err != nil {
			return err
		}
		hello = &clientHelloMsg{}
		if ok := hello.unmarshal(helloBytes); !ok {
			return errors.New("tls: incompatible ClientFingerprintConfiguration")
		}

		// next, let's check if a ClientHello template was provided by the user
	} else if c.config.ExternalClientHello != nil {

		hello = new(clientHelloMsg)

		if !hello.unmarshal(c.config.ExternalClientHello) {
			return errors.New("could not read the ClientHello provided")
		}
		if err := hello.WriteToConfig(c.config); err != nil {
			return err
		}

		// update the SNI with one name, whether or not the extension was already there
		hello.serverName = c.config.ServerName

		// then we update the 'raw' value of the message
		hello.raw = nil
		helloBytes = hello.marshal()

		session = nil
		sessionCache = nil
	} else {
		if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
			return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
		}

		// TODO correctly select nextProtos instead of this static selection
		if c.config.maxVersion() >= VersionTLS13 {
			c.config.NextProtos = append(c.config.NextProtos, "h2")
			c.config.NextProtos = append(c.config.NextProtos, "http/1.1")
		}

		hello = &clientHelloMsg{
			vers:                 c.config.maxVersion(),
			compressionMethods:   []uint8{compressionNone},
			random:               make([]byte, 32),
			ocspStapling:         true,
			serverName:           c.config.ServerName,
			supportedCurves:      c.config.curvePreferences(),
			supportedPoints:      []uint8{pointFormatUncompressed},
			nextProtoNeg:         c.config.maxVersion() < VersionTLS13 && len(c.config.NextProtos) > 0, // TODO do this properly
			secureRenegotiation:  true,
			alpnProtocols:        c.config.NextProtos,
			extendedMasterSecret: c.config.maxVersion() >= VersionTLS10 && c.config.ExtendedMasterSecret,
		}

		if c.config.ForceSessionTicketExt {
			hello.ticketSupported = true
		}
		if c.config.SignedCertificateTimestampExt {
			hello.sctEnabled = true
		}

		if c.config.HeartbeatEnabled && !c.config.ExtendedRandom {
			hello.heartbeatEnabled = true
			hello.heartbeatMode = heartbeatModePeerAllowed
		}

		var possibleCipherSuites []uint16
		// TODO sending TLS 1.3 cipher suites makes the testserver not even responding with an alert ...
		if hello.vers >= VersionTLS13 {
			// TODO c.vers is not set to TLS 1.3 which is inconsistent, but currently saves efforts for adapting all functions depending on it.
			// possibleCipherSuites = c.config.cipherSuites(c.vers)
			possibleCipherSuites = append(possibleCipherSuites, c.config.cipherSuites(VersionTLS13)...)
		}
		// TODO only advertise TLS 1.2 ciphers when we send it in the supported_versions extension
		if true {
			possibleCipherSuites = append(possibleCipherSuites, c.config.cipherSuites(c.vers)...)
		}
		hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

		if c.config.ForceSuites {
			hello.cipherSuites = possibleCipherSuites
		} else {

		NextCipherSuite:
			for _, suiteId := range possibleCipherSuites {
				for _, suite := range implementedCipherSuites {
					if suite.id != suiteId {
						continue
					}
					// Don't advertise TLS 1.2-only cipher suites unless
					// we're attempting TLS 1.2.
					if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
						continue
					}
					hello.cipherSuites = append(hello.cipherSuites, suiteId)
					continue NextCipherSuite
				}
			}
		}

		if len(c.config.ClientRandom) == 32 {
			copy(hello.random, c.config.ClientRandom)
		} else {
			_, err := io.ReadFull(c.config.rand(), hello.random)
			if err != nil {
				c.sendAlert(alertInternalError)
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}

		if c.config.ExtendedRandom {
			hello.extendedRandomEnabled = true
			hello.extendedRandom = make([]byte, 32)
			if _, err := io.ReadFull(c.config.rand(), hello.extendedRandom); err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}

		if hello.vers >= VersionTLS12 {
			hello.signatureAndHashes = c.config.signatureAndHashesForClient()
		}

		sessionCache = c.config.ClientSessionCache
		if c.config.SessionTicketsDisabled {
			sessionCache = nil
		}
		if sessionCache != nil {
			hello.ticketSupported = true

			// Try to resume a previously negotiated TLS session, if
			// available.
			cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
			candidateSession, ok := sessionCache.Get(cacheKey)
			if ok {
				// Check that the ciphersuite/version used for the
				// previous session are still valid.
				cipherSuiteOk := false
				for _, id := range hello.cipherSuites {
					if id == candidateSession.cipherSuite {
						cipherSuiteOk = true
						break
					}
				}

				versOk := candidateSession.vers >= c.config.minVersion() &&
					candidateSession.vers <= c.config.maxVersion()
				if versOk && cipherSuiteOk {
					session = candidateSession
				}
			}
		}

		if session != nil {
			hello.sessionTicket = session.sessionTicket
			// A random session ID is used to detect when the
			// server accepted the ticket and is resuming a session
			// (see RFC 5077).
			hello.sessionId = make([]byte, 16)
			if _, err := io.ReadFull(c.config.rand(), hello.sessionId); err != nil {
				c.sendAlert(alertInternalError)
				return errors.New("tls: short read from Rand: " + err.Error())
			}

		}

		// TODO not part of cloudflares implementation
		if hello.vers >= VersionTLS13 {
			hello.vers = VersionTLS12
			hello.supportedVersions = append(hello.supportedVersions, VersionTLS13)
			hello.supportedVersions = append(hello.supportedVersions, 0x7f00|0x10) // draft 16
			hello.supportedVersions = append(hello.supportedVersions, 0x7f00|0x11) // draft 17
			hello.supportedVersions = append(hello.supportedVersions, 0x7f00|0x12) // draft 18
			hello.supportedVersions = append(hello.supportedVersions, VersionTLS12)

			for _, v := range c.config.curvePreferences() {
				curve, ok := curveForCurveID(v)
				if !ok {
					return errors.New("Unsupported curve")
				}

				_, x, y, err := elliptic.GenerateKey(curve, c.config.rand())
				if err != nil {
					return err
				}

				ecdhePublic := elliptic.Marshal(curve, x, y)
				hello.keyShares = append(hello.keyShares, keyShare{v, ecdhePublic})
			}

			hello.pskModes = append(hello.pskModes, PSKDHE)

			// TODO Client only sends cookie if requested by the server in a HelloRetryRequest
			if false {
				// TODO cookie value must be copied from HelloRetryRequest
				hello.cookie = []byte{1, 2, 3, 4}
			}
		}

		firefox_hello := []byte{
			// 0x16, 0x03, 0x01, 0x02, 0x00,  // header bytes are added by c.writeRecord()
			0x01,	// type (ClientHello)
			0x00, 0x01, 0xfc, // length // TODO adapt
			0x03, 0x03, // version (TLS 1.2)
			0xc4, 0x1b, 0x10, 0x1f, 0x79, 0xe3, 0xd3, 0xd3, 0x2c, 0x90, 0x60, 0x83, 0x92, 0xde, 0x7e, 0x6b,
			0xbb, 0x70, 0xcd, 0x44, 0x5b, 0x88, 0xb8, 0x52, 0x5a, 0x8e, 0x35, 0x06, 0xd0, 0x1b, 0xd4, 0x20, // random (32 byte)
			0x00, // session ID length (0)
			0x00, 0x1c, // cipher suites length (28)
			0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c,
			0xc0, 0x30, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, // cipher suites
			0x01, // compression methods length
			0x00, // compression methods
			0x01, 0xb7, // extensions length
			0x00, 0x00, // type (server name)
				0x00, 0x14, // length // TODO adapt
				0x00, 0x12, // Name list length // TODO adapt
				0x00, // name type (hostname)
				0x00, 0x0f, // name length
				0x74, 0x6c, 0x73, 0x2e, 0x63, 0x74, 0x66, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, // server name // TODO adapt
			0x00, 0x17, // type (extended master secret)
				0x00, 0x00, // length (0)
			0xff, 0x01,  // type (renegotiation info)
				0x00, 0x01, // length
				0x00, // renegotiation info extension length
			0x00, 0x0a, // type (supported groups)
				0x00, 0x0e, // length
				0x00, 0x0c, // list length
				0x00, 0x1d, // group 1
				0x00, 0x17, // group 2
				0x00, 0x18, // group 3
				0x00, 0x19, // group 4
				0x01, 0x00, // group 5
				0x01, 0x01, // group 6
			0x00, 0x0b, // ec point formats
				0x00, 0x02, // length
				0x01, // formats length
				0x00, // format (uncompressed)
			0x00, 0x23, // type (session ticket)
				0x00, 0x00, //length
			0x00, 0x10, // alpn
				0x00, 0x0e, // length
				0x00, 0x0c, // alpn extension length
					0x02, // alpn string len
					0x68, 0x32, // next protocol (h2)
					0x08, //alpn string len
					0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
			0x00, 0x05, // type (status request)
				0x00, 0x05, // len
				0x01, // status type
				0x00, 0x00, // len
				0x00, 0x00, // len
			0x00, 0x12, // signed certificate timestamp
				0x00, 0x00, // len
			0x00, 0x28, // key share
				0x00, 0x6b, // len
				0x00, 0x69, // client key share len
					0x00, 0x1d, // group (ecdh_x25519)
					0x00, 0x20, // key exchange len
					0xfc, 0x53, 0xe7, 0x77, 0x32, 0xe2, 0xe0, 0x4d, 0xd3, 0xa6, 0x7e, 0x49, 0x1a, 0xb9, 0x09, 0x44,
					0x20, 0xf1, 0xab, 0x30, 0x99, 0x6d, 0x3a, 0x5e, 0xf6, 0x74, 0xd7, 0xff, 0xa4, 0x6a, 0x39, 0x09, // key exchange
					0x00, 0x17, // group (secp256r1)
					0x00, 0x41, // key exchange len
					0x04, 0x06, 0x32, 0x28, 0xe5, 0x49, 0xed, 0x69, 0x5e, 0x3f, 0x3e, 0xc4, 0x78, 0x26, 0xbc, 0xab,
					0x63, 0xb3, 0x18, 0xf8, 0x1b, 0x94, 0x8a, 0xda, 0xaf, 0xe3, 0xa7, 0x57, 0xfe, 0x0c, 0xd0, 0x56,
					0xaa, 0x5a, 0x81, 0x29, 0x84, 0x71, 0x33, 0x50, 0x31, 0x00, 0xaa, 0x7c, 0x74, 0xe0, 0x13, 0x06,
					0x15, 0xea, 0xd8, 0x69, 0x0d, 0x56, 0x72, 0xc7, 0xdb, 0xd0, 0x3e, 0x64, 0x8a, 0xd0, 0x8c, 0x99,
					0xdc, // key exchange
			0x00, 0x2b, // supported version
				0x00, 0x09, // length
				0x08, // supported version length
				0x7f, 0x12, // TLS 1.3 (draft 18)
				0x03, 0x03, // TLS 1.2
				0x03, 0x02, // TLS 1.1
				0x03, 0x01, // TLS 1.0
			0x00, 0x0d, // signature algorithms
				0x00, 0x18, // length
				0x00, 0x16, // signature hash algorithms length
					0x04, 0x03, // algorithm 1
					0x05, 0x03, // algorithm 2
					0x06, 0x03, // algorithm 3
					0x08, 0x04, // algorithm 4
					0x08, 0x05, // algorithm 5
					0x08, 0x06, // algorithm 6
					0x04, 0x01, // algorithm 7
					0x05, 0x01, // algorithm 8
					0x06, 0x01, // algorithm 9
					0x02, 0x03, // algorithm 10
					0x02, 0x01, // algorithm 11
			0x00, 0x2d, // psk key exchange modes
				0x00, 0x02, // len
				0x01, // psk key exchange modes length
				0x01, // mode: PSK with (EC)DHE key establishment (psk_dhe_ke)
			0x00, 0x15, // padding
				0x00, 0xb9, // len
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		hello.raw = firefox_hello
		hello.vers = c.config.maxVersion()
		hello.compressionMethods = []uint8{compressionNone}
		hello.ocspStapling = true
		hello.serverName = c.config.ServerName
		hello.supportedCurves = []CurveID{CurveP256}
		hello.supportedPoints = []uint8{pointFormatUncompressed}
		hello.nextProtoNeg = false
		hello.secureRenegotiation = false
		hello.alpnProtocols = []string{"h2", "http/1.1"}
		hello.extendedMasterSecret = true

		hello.ticketSupported = true
		hello.sctEnabled = true
		hello.heartbeatEnabled = true
		hello.heartbeatMode = heartbeatModePeerAllowed
		hello.cipherSuites = []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x002f, 0x0035, 0x000a}
		copy(hello.random, []byte{0xc4, 0x1b, 0x10, 0x1f, 0x79, 0xe3, 0xd3, 0xd3, 0x2c, 0x90, 0x60, 0x83, 0x92, 0xde, 0x7e, 0x6b, 0xbb, 0x70, 0xcd, 0x44, 0x5b, 0x88, 0xb8, 0x52, 0x5a, 0x8e, 0x35, 0x06, 0xd0, 0x1b, 0xd4, 0x20})
		hello.extendedRandomEnabled = false
		// hello.extendedRandom = make([]byte, 32)
		// hello.signatureAndHashes = c.config.signatureAndHashesForClient()
		// hello.ticketSupported = true
		// hello.sessionTicket = session.sessionTicket
		// hello.sessionId = make([]byte, 16)
		// hello.supportedVersions = append(hello.supportedVersions, VersionTLS12)
		// hello.keyShares = append(hello.keyShares, keyShare{v, ecdhePublic})
		// hello.pskModes = append(hello.pskModes, PSKDHE)
		// hello.cookie = []byte{1, 2, 3, 4}
		//helloBytes = hello.marshal()
		helloBytes = firefox_hello
	}

	c.handshakeLog = new(ServerHandshake)
	c.heartbleedLog = new(Heartbleed)
	c.writeRecord(recordTypeHandshake, helloBytes)
	c.handshakeLog.ClientHello = hello.MakeLog()

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	// TODO quick & dirty way to distinguish TLS 1.3 and TLS 1.2 ServerHellos,
	// but requires duplication of the following code, i.e., clientHandshake13()
	// is mainly a code duplication of the rest of this functions code
	serverHello13, ok := msg.(*serverHelloMsg13)
	if ok {
		return c.clientHandshake13(serverHello13, session, hello, cacheKey)
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	c.handshakeLog.ServerHello = serverHello.MakeLog()

	if serverHello.heartbeatEnabled {
		c.heartbeat = true
		c.heartbleedLog.HeartbeatEnabled = true
	}

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", serverHello.vers)
	}
	c.vers = vers
	c.haveVers = true

	suite := mutualCipherSuite(c.config.cipherSuites(c.vers), serverHello.cipherSuite)
	cipherImplemented := cipherIDInCipherList(serverHello.cipherSuite, implementedCipherSuites)
	cipherShared := cipherIDInCipherIDList(serverHello.cipherSuite, c.config.cipherSuites(c.vers))
	if suite == nil {
		// c.sendAlert(alertHandshakeFailure)
		if !cipherShared {
			c.cipherError = ErrNoMutualCipher
		} else if !cipherImplemented {
			c.cipherError = ErrUnimplementedCipher
		}
	}

	hs := &clientHandshakeState{
		c:             c,
		serverHello:   serverHello,
		serverHello13: nil,
		hello:         hello,
		suite:         suite,
		finishedHash:  newFinishedHash(c.vers, suite),
		session:       session,
	}

	// stop here, send alert to peer letting him know that abort is not his fault
	// fmt.Printf("CH/SH done, version %x suite %x\n", vers, suite)
	// c.sendAlert(alertInternalError)

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	if isResume {
		if c.cipherError != nil {
			c.sendAlert(alertHandshakeFailure)
			return c.cipherError
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
	}

	if hs.session == nil {
		c.handshakeLog.SessionTicket = nil
	} else {
		c.handshakeLog.SessionTicket = hs.session.MakeLog()
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	c.didResume = isResume
	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

func (c *Conn) clientHandshake13(serverHello *serverHelloMsg13, session *ClientSessionState, hello *clientHelloMsg, cacheKey string) error {

	sessionCache := c.config.ClientSessionCache

	c.handshakeLog.ServerHello = serverHello.MakeLog()

	// if serverHello.heartbeatEnabled {
	// 	c.heartbeat = true
	// 	c.heartbleedLog.HeartbeatEnabled = true
	// }

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", serverHello.vers)
	}
	c.vers = vers
	c.haveVers = true

	suite := mutualCipherSuite(c.config.cipherSuites(c.vers), serverHello.cipherSuite)
	cipherImplemented := cipherIDInCipherList(serverHello.cipherSuite, implementedCipherSuites)
	cipherShared := cipherIDInCipherIDList(serverHello.cipherSuite, c.config.cipherSuites(c.vers))
	if suite == nil {
		//c.sendAlert(alertHandshakeFailure)
		if !cipherShared {
			c.cipherError = ErrNoMutualCipher
		} else if !cipherImplemented {
			c.cipherError = ErrUnimplementedCipher
		}
	}

	hs := &clientHandshakeState{
		c: c,
		// serverHello:  serverHello,
		serverHello:   nil,
		serverHello13: serverHello,
		hello:         hello,
		suite:         suite,
		finishedHash:  newFinishedHash(c.vers, suite),
		session:       session,
	}

	// stop here, send alert to peer letting him know that abort is not his fault
	// fmt.Printf("CH/SH done, version %x suite %x\n", vers, suite)
	c.sendAlert(alertInternalError)
	// TODO TLS 1.3 handshake not supported yet, aborting here
	return fmt.Errorf("TLS13")

	hs.finishedHash.Write(helloBytes)
	hs.finishedHash.Write(hs.serverHello.marshal())

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	if isResume {
		if c.cipherError != nil {
			c.sendAlert(alertHandshakeFailure)
			return c.cipherError
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
	}

	if hs.session == nil {
		c.handshakeLog.SessionTicket = nil
	} else {
		c.handshakeLog.SessionTicket = hs.session.MakeLog()
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	c.didResume = isResume
	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var serverCert *x509.Certificate

	isAnon := hs.suite != nil && (hs.suite.flags&suiteAnon > 0)

	if !isAnon {

		certMsg, ok := msg.(*certificateMsg)
		if !ok || len(certMsg.certificates) == 0 {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		certs := make([]*x509.Certificate, len(certMsg.certificates))
		invalidCert := false
		var invalidCertErr error
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				invalidCert = true
				invalidCertErr = err
				break
			}
			certs[i] = cert
		}

		c.handshakeLog.ServerCertificates = certMsg.MakeLog()

		if !invalidCert {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}

			// Always check validity of the certificates
			for _, cert := range certs {
				/*
					if i == 0 {
						continue
					}
				*/
				opts.Intermediates.AddCert(cert)
			}
			var validation *x509.Validation
			c.verifiedChains, validation, err = certs[0].ValidateWithStupidDetail(opts)
			c.handshakeLog.ServerCertificates.addParsed(certs, validation)

			// If actually verifying and invalid, reject
			if !c.config.InsecureSkipVerify {
				if err != nil {
					c.sendAlert(alertBadCertificate)
					return err
				}
			}
		}

		if invalidCert {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + invalidCertErr.Error())
		}

		c.peerCertificates = certs

		if hs.serverHello.ocspStapling {
			msg, err = c.readHandshake()
			if err != nil {
				return err
			}
			cs, ok := msg.(*certificateStatusMsg)
			if !ok {
				c.sendAlert(alertUnexpectedMessage)
				return unexpectedMessageError(cs, msg)
			}
			hs.finishedHash.Write(cs.marshal())

			if cs.statusType == statusTypeOCSP {
				c.ocspResponse = cs.response
			}
		}

		serverCert = certs[0]

		var supportedCertKeyType bool
		switch serverCert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, *x509.AugmentedECDSA:
			supportedCertKeyType = true
			break
		case *dsa.PublicKey:
			if c.config.ClientDSAEnabled {
				supportedCertKeyType = true
			}
		default:
			break
		}

		if !supportedCertKeyType {
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", serverCert.PublicKey)
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// If we don't support the cipher, quit before we need to read the hs.suite
	// variable
	if c.cipherError != nil {
		return c.cipherError
	}

	skx, ok := msg.(*serverKeyExchangeMsg)

	keyAgreement := hs.suite.ka(c.vers)

	if ok {
		hs.finishedHash.Write(skx.marshal())

		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, serverCert, skx)
		c.handshakeLog.ServerKeyExchange = skx.MakeLog(keyAgreement)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		// RFC 4346 on the certificateAuthorities field:
		// A list of the distinguished names of acceptable certificate
		// authorities. These distinguished names may specify a desired
		// distinguished name for a root CA or for a subordinate CA;
		// thus, this message can be used to describe both known roots
		// and a desired authorization space. If the
		// certificate_authorities list is empty then the client MAY
		// send any certificate of the appropriate
		// ClientCertificateType, unless there is some external
		// arrangement to the contrary.

		hs.finishedHash.Write(certReq.marshal())

		var rsaAvail, ecdsaAvail bool
		for _, certType := range certReq.certificateTypes {
			switch certType {
			case certTypeRSASign:
				rsaAvail = true
			case certTypeECDSASign:
				ecdsaAvail = true
			}
		}

		// We need to search our list of client certs for one
		// where SignatureAlgorithm is RSA and the Issuer is in
		// certReq.certificateAuthorities
	findCert:
		for i, chain := range c.config.Certificates {
			if !rsaAvail && !ecdsaAvail {
				continue
			}

			for j, cert := range chain.Certificate {
				x509Cert := chain.Leaf
				// parse the certificate if this isn't the leaf
				// node, or if chain.Leaf was nil
				if j != 0 || x509Cert == nil {
					if x509Cert, err = x509.ParseCertificate(cert); err != nil {
						c.sendAlert(alertInternalError)
						return errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
					}
				}

				switch {
				case rsaAvail && x509Cert.PublicKeyAlgorithm == x509.RSA:
				case ecdsaAvail && x509Cert.PublicKeyAlgorithm == x509.ECDSA:
				default:
					continue findCert
				}

				if len(certReq.certificateAuthorities) == 0 {
					// they gave us an empty list, so just take the
					// first RSA cert from c.config.Certificates
					chainToSend = &chain
					break findCert
				}

				for _, ca := range certReq.certificateAuthorities {
					if bytes.Equal(x509Cert.RawIssuer, ca) {
						chainToSend = &chain
						break findCert
					}
				}
			}
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg := new(certificateMsg)
		if chainToSend != nil {
			certMsg.certificates = chainToSend.Certificate
		}
		hs.finishedHash.Write(certMsg.marshal())
		c.writeRecord(recordTypeHandshake, certMsg.marshal())
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, serverCert)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.handshakeLog.ClientKeyExchange = ckx.MakeLog(keyAgreement)

	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		c.writeRecord(recordTypeHandshake, ckx.marshal())
	}

	if chainToSend != nil {
		var signed []byte
		certVerify := &certificateVerifyMsg{
			hasSignatureAndHash: c.vers >= VersionTLS12,
		}

		// Determine the hash to sign.
		var signatureType uint8
		switch c.config.Certificates[0].PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			signatureType = signatureECDSA
		case *rsa.PrivateKey:
			signatureType = signatureRSA
		default:
			c.sendAlert(alertInternalError)
			return errors.New("unknown private key type")
		}
		certVerify.signatureAndHash, err = hs.finishedHash.selectClientCertSignatureAlgorithm(certReq.signatureAndHashes, c.config.signatureAndHashesForClient(), signatureType)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		digest, hashFunc, err := hs.finishedHash.hashForClientCertificate(certVerify.signatureAndHash, hs.masterSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		switch key := c.config.Certificates[0].PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			var r, s *big.Int
			r, s, err = ecdsa.Sign(c.config.rand(), key, digest)
			if err == nil {
				signed, err = asn1.Marshal(ecdsaSignature{r, s})
			}
		case *rsa.PrivateKey:
			signed, err = rsa.SignPKCS1v15(c.config.rand(), key, hashFunc, digest)
		default:
			err = errors.New("unknown private key type")
		}
		if err != nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: failed to sign handshake with client certificate: " + err.Error())
		}
		certVerify.signature = signed

		hs.writeClientHash(certVerify.marshal())
		c.writeRecord(recordTypeHandshake, certVerify.marshal())
	}

	var cr, sr []byte
	if hs.hello.extendedRandomEnabled {
		helloRandomLen := len(hs.hello.random)
		helloExtendedRandomLen := len(hs.hello.extendedRandom)

		cr = make([]byte, helloRandomLen+helloExtendedRandomLen)
		copy(cr, hs.hello.random)
		copy(cr[helloRandomLen:], hs.hello.extendedRandom)
	}

	if hs.serverHello.extendedRandomEnabled {
		serverRandomLen := len(hs.serverHello.random)
		serverExtendedRandomLen := len(hs.serverHello.extendedRandom)

		sr = make([]byte, serverRandomLen+serverExtendedRandomLen)
		copy(sr, hs.serverHello.random)
		copy(sr[serverRandomLen:], hs.serverHello.extendedRandom)
	}

	hs.preMasterSecret = make([]byte, len(preMasterSecret))
	copy(hs.preMasterSecret, preMasterSecret)

	if hs.serverHello.extendedMasterSecret && c.vers >= VersionTLS10 {
		hs.masterSecret = extendedMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.finishedHash)
		c.extendedMasterSecret = true
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	}

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV := keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}

	if hs.serverResumedSession() {
		// Restore masterSecret and peerCerts from previous state
		hs.masterSecret = hs.session.masterSecret
		c.extendedMasterSecret = hs.session.extendedMasterSecret
		c.peerCertificates = hs.session.serverCertificates
		return true, nil
	}
	return false, nil
}

func (hs *clientHandshakeState) readFinished() error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.in.error(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	c.handshakeLog.ServerFinished = serverFinished.MakeLog()

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		lifetimeHint:       sessionTicketMsg.lifetimeHint,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished() error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		c.writeRecord(recordTypeHandshake, nextProto.marshal())
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())

	c.handshakeLog.ClientFinished = finished.MakeLog()

	c.writeRecord(recordTypeHandshake, finished.marshal())
	return nil
}

func (hs *clientHandshakeState) writeClientHash(msg []byte) {
	// writeClientHash is called before writeRecord.
	hs.writeHash(msg, 0)
}

func (hs *clientHandshakeState) writeServerHash(msg []byte) {
	// writeServerHash is called after readHandshake.
	hs.writeHash(msg, 0)
}

func (hs *clientHandshakeState) writeHash(msg []byte, seqno uint16) {
	hs.finishedHash.Write(msg)
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// mutualProtocol finds the mutual Next Protocol Negotiation or ALPN protocol
// given list of possible protocols and a list of the preference order. The
// first list must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
func mutualProtocol(protos, preferenceProtos []string) (string, bool) {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s, false
			}
		}
	}

	return protos[0], true
}
