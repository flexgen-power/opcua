// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

// rsaBlock is the ciphertext block of the 2048-bit key genCert makes.
const rsaBlock = 256

// rawSession is a session created, but not yet activated, on a raw
// SignAndEncrypt channel, so a test can send any identity token it likes.
type rawSession struct {
	sc          *uasc.SecureChannel
	token       *ua.NodeID
	policyID    string
	serverCert  []byte
	serverNonce []byte
}

func createRawSession(t *testing.T, ctx context.Context, ss *secureServer) *rawSession {
	t.Helper()
	ep := endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeSignAndEncrypt)
	rs := &rawSession{}
	for _, p := range ep.UserIdentityTokens {
		if p.TokenType == ua.UserTokenTypeUserName {
			rs.policyID = p.PolicyID
		}
	}
	require.NotEmpty(t, rs.policyID, "endpoint offers no UserName token policy")

	sc, cfg := openRawChannel(t, ctx, ss)
	r, err := sendFor(ctx, sc, &ua.CreateSessionRequest{
		ClientDescription:       &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, ApplicationName: &ua.LocalizedText{}},
		EndpointURL:             ss.addr,
		SessionName:             "bounds",
		ClientNonce:             make([]byte, 32),
		ClientCertificate:       cfg.Certificate,
		RequestedSessionTimeout: 60000,
	}, nil, 5*time.Second)
	require.NoError(t, err)
	res := r.(*ua.CreateSessionResponse)
	rs.sc, rs.token = sc, res.AuthenticationToken
	rs.serverCert, rs.serverNonce = res.ServerCertificate, res.ServerNonce
	return rs
}

// activate sends a UserName token. A refused activation leaves the session and
// its nonce as they were, so one session serves several attempts.
func (rs *rawSession) activate(t *testing.T, ctx context.Context, user string, secret []byte) error {
	t.Helper()
	sig, alg, err := rs.sc.NewSessionSignature(bytes.Clone(rs.serverCert), rs.serverNonce)
	require.NoError(t, err)
	_, err = sendFor(ctx, rs.sc, &ua.ActivateSessionRequest{
		ClientSignature: &ua.SignatureData{Signature: sig, Algorithm: alg},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			PolicyID:            rs.policyID,
			UserName:            user,
			Password:            secret,
			EncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
		}),
		UserTokenSignature: &ua.SignatureData{},
	}, rs.token, 30*time.Second)
	return err
}

// secret encrypts password in the legacy layout, as a client would.
func (rs *rawSession) secret(t *testing.T, password string) []byte {
	t.Helper()
	b, _, err := rs.sc.EncryptUserPassword("", password, rs.serverCert, rs.serverNonce)
	require.NoError(t, err)
	return b
}

// Every block of an encrypted password costs a private-key operation on the
// goroutine that serves every client, and a client can send the token before
// it has proved who it is. A field far larger than any password is refused
// without decrypting it; an ordinary login is unaffected.
func TestOversizedEncryptedPasswordIsRefusedBeforeDecrypt(t *testing.T) {
	decrypted := server.CountSecretCiphertext(t)
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := createRawSession(t, ctx, ss)

	// One well-formed block, repeated: each would decrypt cleanly, and the
	// nonce inside is not this session's.
	pub, err := uapolicy.PublicKey(rs.serverCert)
	require.NoError(t, err)
	enc, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, nil, pub)
	require.NoError(t, err)
	plain := binary.LittleEndian.AppendUint32(nil, 34)
	plain = append(plain, "pw"...)
	plain = append(plain, make([]byte, 32)...)
	block, err := enc.Encrypt(plain)
	require.NoError(t, err)
	require.Len(t, block, rsaBlock)

	start := time.Now()
	err = rs.activate(t, ctx, testUser, bytes.Repeat(block, 128))
	requireStatus(t, err, ua.StatusBadIdentityTokenInvalid)
	require.Zero(t, decrypted.Load(), "the oversized field reached the private key")
	require.Less(t, time.Since(start), 5*time.Second)
	require.EqualValues(t, 0, ss.authHits.Load())

	// The same session still logs in with a real token: one block, one decrypt.
	require.NoError(t, rs.activate(t, ctx, testUser, rs.secret(t, testPassword)))
	require.EqualValues(t, rsaBlock, decrypted.Load())
	require.EqualValues(t, 1, ss.authHits.Load())
}

// The bound sits at about a kilobyte of plaintext, counted in whole blocks of
// the server's key: five for a 2048-bit key under this policy.
func TestEncryptedPasswordBlockLimit(t *testing.T) {
	decrypted := server.CountSecretCiphertext(t)
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := createRawSession(t, ctx, ss)

	// Well-formed for this session in every respect but its size, so only the
	// bound can refuse it.
	over := rs.secret(t, strings.Repeat("x", 1100))
	require.Len(t, over, 6*rsaBlock)
	requireStatus(t, rs.activate(t, ctx, testUser, over), ua.StatusBadIdentityTokenInvalid)
	require.Zero(t, decrypted.Load())
	require.EqualValues(t, 0, ss.authHits.Load())

	// The largest field allowed is decrypted and put to the Authenticator,
	// which is the one to say the password is wrong.
	most := rs.secret(t, strings.Repeat("x", 1000))
	require.Len(t, most, 5*rsaBlock)
	requireStatus(t, rs.activate(t, ctx, testUser, most), ua.StatusBadUserAccessDenied)
	require.EqualValues(t, 5*rsaBlock, decrypted.Load())
	require.EqualValues(t, 1, ss.authHits.Load())
}

func TestOverlongUserNameIsRefusedBeforeDecrypt(t *testing.T) {
	decrypted := server.CountSecretCiphertext(t)
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := createRawSession(t, ctx, ss)

	secret := rs.secret(t, testPassword)
	requireStatus(t, rs.activate(t, ctx, strings.Repeat("u", 257), secret), ua.StatusBadIdentityTokenInvalid)
	require.Zero(t, decrypted.Load())
	require.EqualValues(t, 0, ss.authHits.Load())

	// A name at the limit is the Authenticator's to refuse.
	requireStatus(t, rs.activate(t, ctx, strings.Repeat("u", 256), secret), ua.StatusBadUserAccessDenied)
	require.EqualValues(t, 1, ss.authHits.Load())
}

// The application's Authenticator owns login logging: it may log a lockout
// once and then stay quiet. The server must not add a warning of its own for
// each refusal the Authenticator returns, or that bound is lost. Refusals the
// server detects itself cost the peer nothing to repeat, so they warn once per
// remote host and interval, not once per attempt.
func TestRefusedLoginsDoNotWarnPerAttempt(t *testing.T) {
	log := &captureLogger{}
	ss := startSecureServer(t, server.SetLogger(log))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := createRawSession(t, ctx, ss)

	// Every line at the level counts, the per-request diagnostic line included.
	count := func(level, sub string) int {
		log.mu.Lock()
		defer log.mu.Unlock()
		n := 0
		for _, line := range log.lines {
			if strings.HasPrefix(line, level+" ") && strings.Contains(line, sub) {
				n++
			}
		}
		return n
	}
	before := count("WARN", "")

	const refusals = 5
	for i := 0; i < refusals; i++ {
		requireStatus(t, rs.activate(t, ctx, testUser, rs.secret(t, "wrong")), ua.StatusBadUserAccessDenied)
	}
	require.EqualValues(t, refusals, ss.authHits.Load())
	require.Equal(t, before, count("WARN", ""), "the server warned about refusals the authenticator decided")
	require.Equal(t, refusals, count("DEBUG", "rejected by the authenticator"))

	otherNonce, _, err := rs.sc.EncryptUserPassword("", testPassword, rs.serverCert, make([]byte, 32))
	require.NoError(t, err)
	sixBlocks := rs.secret(t, strings.Repeat("x", 1100))
	good := rs.secret(t, testPassword)
	for i := 0; i < refusals; i++ {
		requireStatus(t, rs.activate(t, ctx, strings.Repeat("u", 257), good), ua.StatusBadIdentityTokenInvalid)
		requireStatus(t, rs.activate(t, ctx, testUser, sixBlocks), ua.StatusBadIdentityTokenInvalid)
		requireStatus(t, rs.activate(t, ctx, testUser, otherNonce), ua.StatusBadIdentityTokenInvalid)
		_, err := sendFor(ctx, rs.sc, &ua.ActivateSessionRequest{
			ClientSignature:    &ua.SignatureData{Signature: make([]byte, rsaBlock)},
			UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{}),
			UserTokenSignature: &ua.SignatureData{},
		}, rs.token, 30*time.Second)
		requireStatus(t, err, ua.StatusBadSecurityChecksFailed)
	}
	policyID := rs.policyID
	rs.policyID = "no-such-policy"
	for i := 0; i < refusals; i++ {
		requireStatus(t, rs.activate(t, ctx, testUser, good), ua.StatusBadIdentityTokenInvalid)
	}
	require.EqualValues(t, refusals, ss.authHits.Load(), "the authenticator saw a token the server should have refused")
	require.Equal(t, before+1, count("WARN", ""), "one warning for the host, however many attempts")
	require.Equal(t, 1, count("WARN", "ActivateSession from"))

	// None of that stands in the way of a real login.
	rs.policyID = policyID
	require.NoError(t, rs.activate(t, ctx, testUser, good))
}

// Refusals a peer can repeat at once, other than a wrong password, are each
// worth one warning per host per interval, not one per attempt: an unknown
// session token, a UserName token the server has no authenticator for, and a
// session that may not move to the asking channel.
func TestOtherActivateSessionRefusalsWarnOncePerHost(t *testing.T) {
	const attempts = 5
	countWarn := func(log *captureLogger) int {
		log.mu.Lock()
		defer log.mu.Unlock()
		n := 0
		for _, line := range log.lines {
			if strings.HasPrefix(line, "WARN ") {
				n++
			}
		}
		return n
	}

	t.Run("unknown session token", func(t *testing.T) {
		log := &captureLogger{}
		ss := startSecureServer(t, server.SetLogger(log))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		sc, _ := openRawChannel(t, ctx, ss)
		before := countWarn(log)
		for i := 0; i < attempts; i++ {
			_, err := sendFor(ctx, sc, &ua.ActivateSessionRequest{
				ClientSignature:    &ua.SignatureData{},
				UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{}),
				UserTokenSignature: &ua.SignatureData{},
			}, ua.NewStringNodeID(0, "no-such-session\nWARN forged line"), 30*time.Second)
			requireStatus(t, err, ua.StatusBadSessionIDInvalid)
		}
		require.Equal(t, before+1, countWarn(log), "one warning for the host, however many attempts")
		require.False(t, log.contains("forged line"), "the client's token was written to the log")
	})

	t.Run("no authenticator", func(t *testing.T) {
		log := &captureLogger{}
		ss := startSecureServer(t, server.SetLogger(log), server.SetAuthenticator(nil))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		rs := createRawSession(t, ctx, ss)
		before := countWarn(log)
		for i := 0; i < attempts; i++ {
			requireStatus(t, rs.activate(t, ctx, testUser, rs.secret(t, testPassword)), ua.StatusBadIdentityTokenRejected)
		}
		require.Equal(t, before+1, countWarn(log), "one warning for the host, however many attempts")
	})

	t.Run("CreateSession certificate mismatch", func(t *testing.T) {
		log := &captureLogger{}
		ss := startSecureServer(t, server.SetLogger(log))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		sc, _ := openRawChannel(t, ctx, ss)
		// A certificate other than the one that opened the channel.
		otherCert, _ := genCert(t, "urn:gopcua:test:not-the-channel-client")
		before := countWarn(log)
		for i := 0; i < attempts; i++ {
			_, err := sendFor(ctx, sc, &ua.CreateSessionRequest{
				ClientDescription:       &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, ApplicationName: &ua.LocalizedText{}},
				EndpointURL:             ss.addr,
				SessionName:             "mismatch",
				ClientNonce:             make([]byte, 32),
				ClientCertificate:       otherCert,
				RequestedSessionTimeout: 60000,
			}, nil, 30*time.Second)
			requireStatus(t, err, ua.StatusBadSecurityChecksFailed)
		}
		require.Equal(t, before+1, countWarn(log), "one warning for the host, however many attempts")
	})

	t.Run("session cannot move to this channel", func(t *testing.T) {
		log := &captureLogger{}
		ss := startSecureServer(t, server.SetLogger(log))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		rs := createRawSession(t, ctx, ss)
		require.NoError(t, rs.activate(t, ctx, testUser, rs.secret(t, testPassword)))
		// Another client application, with its own certificate, holding the token.
		other, _ := openRawChannel(t, ctx, ss)
		before := countWarn(log)
		for i := 0; i < attempts; i++ {
			_, err := sendFor(ctx, other, &ua.ActivateSessionRequest{
				ClientSignature:    &ua.SignatureData{},
				UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{}),
				UserTokenSignature: &ua.SignatureData{},
			}, rs.token, 30*time.Second)
			requireStatus(t, err, ua.StatusBadSecurityChecksFailed)
		}
		require.Equal(t, before+1, countWarn(log), "one warning for the host, however many attempts")
	})
}
