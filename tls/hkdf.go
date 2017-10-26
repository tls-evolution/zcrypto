// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Mostly derived from golang.org/x/crypto/hkdf, but with an exposed
// Extract API.
//
// HKDF is a cryptographic key derivation function (KDF) with the goal of
// expanding limited input keying material into one or more cryptographically
// strong secret keys.
//
// RFC 5869: https://tools.ietf.org/html/rfc5869

import (
	"crypto"
	"crypto/hmac"
)

func hkdfExpand(hash crypto.Hash, prk, info []byte, l int) []byte {
	var (
		expander = hmac.New(hash.New, prk)
		res      = make([]byte, l)
		counter  = byte(1)
		prev     []byte
	)

	if l > 255*expander.Size() {
		panic("hkdf: requested too much output")
	}

	p := res
	for len(p) > 0 {
		expander.Reset()
		expander.Write(prev)
		expander.Write(info)
		expander.Write([]byte{counter})
		prev = expander.Sum(prev[:0])
		counter++
		n := copy(p, prev)
		p = p[n:]
	}

	return res
}

func hkdfExtract(hash crypto.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash.Size())
	}
	if secret == nil {
		secret = make([]byte, hash.Size())
	}
	extractor := hmac.New(hash.New, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}

func hkdfExpandLabel(hash crypto.Hash, secret []byte, label string, hashValue []byte, L int) []byte {
	hkdfLable := make([]byte, 4+len("tls13")+len(label)+len(hashValue))
	hkdfLable[0] = byte(L >> 8)
	hkdfLable[1] = byte(L)
	hkdfLable[2] = byte(len("tls13") + len(label))
	copy(hkdfLable[3:], "tls13")
	z := hkdfLable[3+len("tls13"):]
	copy(z, label)
	z = z[len(label):]
	//z[0] = byte(len(hashValue))
	copy(z, hashValue)
	return hkdfExpand(hash, secret, hkdfLable, L)
}

func deriveSecrete(hash crypto.Hash, secret []byte, label string, hashValue []byte) []byte {
	return hkdfExpandLabel(hash, secret, label, hashValue, hash.Size())
}
