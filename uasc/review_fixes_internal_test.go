// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

// A renewal waits for requests already being sent and holds back new ones
// until it ends.
func TestSendGate(t *testing.T) {
	g := newSendGate()
	g.enter()

	renewing := make(chan struct{})
	go func() {
		g.beginRenew()
		close(renewing)
	}()
	select {
	case <-renewing:
		t.Fatal("renewal began while a request was still being sent")
	case <-time.After(50 * time.Millisecond):
	}

	g.leave()
	select {
	case <-renewing:
	case <-time.After(time.Second):
		t.Fatal("renewal did not begin once the request was sent")
	}

	entered := make(chan struct{})
	go func() {
		g.enter()
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("a request was sent during the renewal")
	case <-time.After(50 * time.Millisecond):
	}

	g.endRenew()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the held request was not let through after the renewal")
	}
	g.leave()
}

func certFor(t *testing.T, cn string, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	return der
}

// The client signs the server certificate it was given followed by the nonce.
// When the server presents a chain, a client following Part 4, 5.6.3.2 signs
// the leaf only; this package's own client signs the whole blob. Both verify.
func TestVerifySessionSignatureOverAChain(t *testing.T) {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leaf := certFor(t, "server", &serverKey.PublicKey, serverKey)
	chain := append(append([]byte{}, leaf...), certFor(t, "ca", &caKey.PublicKey, caKey)...)
	clientCert := certFor(t, "client", &clientKey.PublicKey, clientKey)

	s := &SecureChannel{cfg: &Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		LocalKey:          serverKey,
		Certificate:       chain,
	}}
	clientSide, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, clientKey, &serverKey.PublicKey)
	require.NoError(t, err)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	sign := func(data []byte) []byte {
		sig, err := clientSide.Signature(append(append([]byte{}, data...), nonce...))
		require.NoError(t, err)
		return sig
	}

	require.NoError(t, s.VerifySessionSignature(clientCert, nonce, sign(leaf)), "signature over the leaf")
	require.NoError(t, s.VerifySessionSignature(clientCert, nonce, sign(chain)), "signature over the whole chain")
	require.Error(t, s.VerifySessionSignature(clientCert, nonce, sign([]byte("something else"))))
}

// A peer's certificate with a key that is not RSA is an error, not a panic.
func TestSessionSignaturesRefuseANonRSACertificate(t *testing.T) {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecCert := certFor(t, "ecdsa", &ecKey.PublicKey, ecKey)

	s := &SecureChannel{cfg: &Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		LocalKey:          serverKey,
		UserKey:           serverKey,
		Certificate:       certFor(t, "server", &serverKey.PublicKey, serverKey),
	}}
	require.Error(t, s.VerifySessionSignature(ecCert, make([]byte, 32), []byte("sig")))
	_, _, err = s.NewSessionSignature(ecCert, make([]byte, 32))
	require.Error(t, err)
	_, _, err = s.EncryptUserPassword("", "pw", ecCert, make([]byte, 32))
	require.Error(t, err)
	_, _, err = s.NewUserTokenSignature("", ecCert, make([]byte, 32))
	require.Error(t, err)
}
