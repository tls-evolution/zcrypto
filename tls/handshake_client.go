// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/zmap/zcrypto/x509"
)

type clientHandshakeState struct {
	c               *Conn
	hello           *clientHelloMsg
	suite           *cipherSuite
	masterSecret    []byte
	preMasterSecret []byte
	session         *ClientSessionState

	// TLS 1.0-1.2 fields
	serverHello  *serverHelloMsg
	finishedHash finishedHash

	// TLS 1.3 fields
	serverHello13 *serverHelloMsg13
	keySchedule   *keySchedule13
	privateKey    []byte
}

func makeClientHello(config *Config) (*clientHelloMsg, error) {
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return nil, errors.New("tls: NextProtos values too large")
	}

	hello := &clientHelloMsg{
		vers:                         config.maxVersion(),
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(),
		supportedPoints:              []uint8{pointFormatUncompressed},
		nextProtoNeg:                 len(config.NextProtos) > 0,
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
	}
	possibleCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				continue NextCipherSuite
			}
			// Don't advertise TLS 1.3-only cipher suites unless
			// we're attempting TLS 1.3.
			if hello.vers < VersionTLS13 && suite.flags&suiteTLS13 != 0 {
				continue NextCipherSuite
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}
	// TODO fix PSS support for certificates and advertise these algorithms
	// in the global supportedSignatureAlgorithms.
	if hello.vers >= VersionTLS13 {
		hello.supportedSignatureAlgorithms =
			append([]SignatureScheme{PSSWithSHA256, PSSWithSHA384},
				hello.supportedSignatureAlgorithms...)
	}

	return hello, nil
}

// c.out.Mutex <= L; c.handshakeMutex <= L.
func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	hello, err := makeClientHello(c.config)
	if err != nil {
		return err
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	var session *ClientSessionState
	var cacheKey string
	sessionCache := c.config.ClientSessionCache
	// TLS 1.3 has no session resumption based on session tickets.
	if c.config.SessionTicketsDisabled || c.config.maxVersion() >= VersionTLS13 {
		sessionCache = nil
	}

	if sessionCache != nil {
		hello.ticketSupported = true
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if sessionCache != nil && c.handshakes == 0 {
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
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	var privateKey []byte
	var clientKS keyShare
	if c.config.maxVersion() >= VersionTLS13 {
		// Version preference is indicated via "supported_extensions",
		// set legacy_version to TLS 1.2 for backwards compatibility.
		hello.vers = VersionTLS12
		hello.supportedVersions = c.config.getSupportedVersions()
		// Create one keyshare for the first default curve. If it is not
		// appropriate, the server should raise a HRR.
		defaultGroup := c.config.curvePreferences()[0]
		privateKey, clientKS, err = c.config.generateKeyShare(defaultGroup)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hello.keyShares = []keyShare{clientKS}
	}

	hs := &clientHandshakeState{
		c:          c,
		hello:      hello,
		session:    session,
		privateKey: privateKey,
	}

	if err = hs.handshake(); err != nil {
		return err
	}

	if hs.session == nil {
		c.handshakeLog.SessionTicket = nil
	} else {
		c.handshakeLog.SessionTicket = hs.session.MakeLog()
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one
	if sessionCache != nil && hs.session != nil && session != hs.session && c.vers < VersionTLS13 {
		sessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

// Does the handshake, either a full one or resumes old session.
// Requires hs.c, hs.hello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c
	c.handshakeLog = new(ServerHandshake)
	c.heartbleedLog = new(Heartbleed)

	var hrrMsg *helloRetryRequestMsg
	var hello1 []uint8

	// send ClientHello
retry:
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}
	c.handshakeLog.ClientHello = hs.hello.MakeLog()

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var vers, cipherSuite uint16
	switch m := msg.(type) {
	case *serverHelloMsg:
		hs.serverHello = m
		c.handshakeLog.ServerHello = m.MakeLog()
		vers = m.vers
		cipherSuite = m.cipherSuite
	case *serverHelloMsg13:
		hs.serverHello13 = m
		c.handshakeLog.ServerHello = m.MakeLog()
		vers = m.vers
		cipherSuite = m.cipherSuite
	case *helloRetryRequestMsg:
		if m.cookie != nil {
			copy(hs.hello.cookie, m.cookie)
		}
		// generate new stuff here
		privateKey, clientKS, err := c.config.generateKeyShare(m.keyShare.group)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.privateKey = privateKey
		hs.hello.keyShares = []keyShare{clientKS}
		hello1 = hs.hello.marshal()
		hs.hello.raw = nil // prevent using outdated, cached copy
		hrrMsg = m
		goto retry
	default:
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(hs.serverHello, msg)
	}

	if err = hs.pickTLSVersion(vers); err != nil {
		return err
	}

	if err = hs.pickCipherSuite(cipherSuite); err != nil {
		return err
	}

	if c.vers >= VersionTLS13 {
		hs.keySchedule = newKeySchedule13(hs.suite, c.config, hs.hello.random, c.vers)
		if hrrMsg != nil {
			if c.vers >= VersionTLS13Draft19 {
				hs.keySchedule.writeMessageHash(hello1)
				hs.keySchedule.write(hrrMsg.marshal())
			} else {
				hs.keySchedule.write(hello1)
				hs.keySchedule.write(hrrMsg.marshal())
			}
		}
		hs.keySchedule.write(hs.hello.marshal())
		hs.keySchedule.write(hs.serverHello13.marshal())
	}

	var isResume bool
	if !(c.vers >= VersionTLS13) {
		hs.finishedHash = newFinishedHash(c.vers, hs.suite)

		isResume, err = hs.processServerHello()
		if err != nil {
			return err
		}

		// No signatures of the handshake are needed in a resumption.
		// Otherwise, in a full handshake, if we don't have any certificates
		// configured then we will never send a CertificateVerify message and
		// thus no signatures are needed in that case either.
		if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
			hs.finishedHash.discardHandshakeBuffer()
		}

		hs.finishedHash.Write(hs.hello.marshal())
		hs.finishedHash.Write(hs.serverHello.marshal())
	}

	c.buffering = true
	if c.vers >= VersionTLS13 {
		if err := hs.doTLS13Handshake(); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.didResume = isResume
	c.phase = handshakeConfirmed
	atomic.StoreInt32(&c.handshakeConfirmed, 1)
	c.handshakeComplete = true

	return nil
}

func (hs *clientHandshakeState) pickTLSVersion(ver uint16) error {
	vers, ok := hs.c.config.pickVersion([]uint16{ver})
	if !ok || vers < VersionTLS10 {
		// TLS 1.0 is the minimum version supported as a client.
		hs.c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", hs.serverHello.vers)
	}

	hs.c.vers = vers
	hs.c.haveVers = true

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite(suite uint16) error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, suite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	// Check that the chosen cipher suite matches the protocol version.
	if hs.c.vers >= VersionTLS13 && hs.suite.flags&suiteTLS13 == 0 ||
		hs.c.vers < VersionTLS13 && hs.suite.flags&suiteTLS13 != 0 {
		hs.c.sendAlert(alertHandshakeFailure)
		fmt.Printf("Server (ver %d) chose: %04x\n", hs.c.vers, hs.suite.id)
		return errors.New("tls: server chose an inappropriate cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

// processCertsFromServer takes a chain of server certificates from a
// Certificate message and verifies them.
func (hs *clientHandshakeState) processCertsFromServer(certificates [][]byte) error {
	c := hs.c
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		for i, cert := range certs {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}
		var err error
		var validation *x509.Validation
		c.verifiedChains, validation, err = certs[0].ValidateWithStupidDetail(opts)
		c.handshakeLog.ServerCertificates.addParsed(certs, validation)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, *x509.AugmentedECDSA:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		c.handshakeLog.ServerCertificates = certMsg.MakeLog()
		if err := hs.processCertsFromServer(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

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

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
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
		hs.finishedHash.Write(certReq.marshal())

		if chainToSend, err = hs.getCertificate(certReq); err != nil {
			c.sendAlert(alertInternalError)
			return err
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
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.handshakeLog.ClientKeyExchange = ckx.MakeLog(keyAgreement)

	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{
			hasSignatureAndHash: c.vers >= VersionTLS12,
		}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var signatureType uint8
		switch key.Public().(type) {
		case *ecdsa.PublicKey:
			signatureType = signatureECDSA
		case *rsa.PublicKey:
			signatureType = signatureRSA
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: failed to sign handshake with client certificate: unknown client certificate key type: %T", key)
		}

		// SignatureAndHashAlgorithm was introduced in TLS 1.2.
		if certVerify.hasSignatureAndHash {
			certVerify.signatureAlgorithm, err = hs.finishedHash.selectClientCertSignatureAlgorithm(certReq.supportedSignatureAlgorithms, signatureType)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
		}
		digest, hashFunc, err := hs.finishedHash.hashForClientCertificate(signatureType, certVerify.signatureAlgorithm, hs.masterSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		certVerify.signature, err = key.Sign(c.config.rand(), digest, hashFunc)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.preMasterSecret = make([]byte, len(preMasterSecret))
	copy(hs.preMasterSecret, preMasterSecret)

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog("CLIENT_RANDOM", hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
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

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
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
	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
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
		c.sendAlert(alertDecryptError)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
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
		verifiedChains:     c.verifiedChains,
		lifetimeHint:       sessionTicketMsg.lifetimeHint,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())

	c.handshakeLog.ClientFinished = finished.MakeLog()

	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// tls11SignatureSchemes contains the signature schemes that we synthesise for
// a TLS <= 1.1 connection, based on the supported certificate types.
var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}

const (
	// tls11SignatureSchemesNumECDSA is the number of initial elements of
	// tls11SignatureSchemes that use ECDSA.
	tls11SignatureSchemesNumECDSA = 3
	// tls11SignatureSchemesNumRSA is the number of trailing elements of
	// tls11SignatureSchemes that use RSA.
	tls11SignatureSchemesNumRSA = 4
)

func (hs *clientHandshakeState) getCertificate(certReq *certificateRequestMsg) (*Certificate, error) {
	c := hs.c

	var rsaAvail, ecdsaAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecdsaAvail = true
		}
	}

	if c.config.GetClientCertificate != nil {
		var signatureSchemes []SignatureScheme

		if !certReq.hasSignatureAndHash {
			// Prior to TLS 1.2, the signature schemes were not
			// included in the certificate request message. In this
			// case we use a plausible list based on the acceptable
			// certificate types.
			signatureSchemes = tls11SignatureSchemes
			if !ecdsaAvail {
				signatureSchemes = signatureSchemes[tls11SignatureSchemesNumECDSA:]
			}
			if !rsaAvail {
				signatureSchemes = signatureSchemes[:len(signatureSchemes)-tls11SignatureSchemesNumRSA]
			}
		} else {
			signatureSchemes = certReq.supportedSignatureAlgorithms
		}

		return c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    certReq.certificateAuthorities,
			SignatureSchemes: signatureSchemes,
		})
	}

	// RFC 4346 on the certificateAuthorities field: A list of the
	// distinguished names of acceptable certificate authorities.
	// These distinguished names may specify a desired
	// distinguished name for a root CA or for a subordinate CA;
	// thus, this message can be used to describe both known roots
	// and a desired authorization space. If the
	// certificate_authorities list is empty then the client MAY
	// send any certificate of the appropriate
	// ClientCertificateType, unless there is some external
	// arrangement to the contrary.

	// We need to search our list of client certs for one
	// where SignatureAlgorithm is acceptable to the server and the
	// Issuer is in certReq.certificateAuthorities
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
				var err error
				if x509Cert, err = x509.ParseCertificate(cert); err != nil {
					c.sendAlert(alertInternalError)
					return nil, errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
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
				// first cert from c.config.Certificates
				return &chain, nil
			}

			for _, ca := range certReq.certificateAuthorities {
				if bytes.Equal(x509Cert.RawIssuer, ca) {
					return &chain, nil
				}
			}
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
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

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See https://tools.ietf.org/html/rfc6066#section-3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
