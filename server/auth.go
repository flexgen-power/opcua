// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

// UserIdentity is the identity a client presented in ActivateSession, after the
// server has matched it to an advertised user token policy, decrypted it and
// checked its proof of possession.
type UserIdentity struct {
	// TokenType is UserName or Certificate; Anonymous tokens never reach an
	// Authenticator.
	TokenType ua.UserTokenType
	PolicyID  string

	// Username and Password are set for UserName tokens. Password is the
	// decrypted plaintext and is wiped once the Authenticator returns.
	Username string
	Password []byte

	// Certificate is the DER user certificate of a Certificate token. The
	// server has verified the client holds its private key; whether the
	// certificate itself is trusted is the Authenticator's decision.
	Certificate []byte

	// ClientCertificate is the application instance certificate of the secure
	// channel, nil on a None channel.
	ClientCertificate []byte
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	RemoteAddr        string
}

// Authenticator decides whether an identity may activate a session. It runs
// on the server's request dispatcher, so it should return quickly. Returning
// nil accepts. A returned ua.StatusCode is sent to the client as is; any other
// error is sent as BadUserAccessDenied.
type Authenticator func(UserIdentity) error

// SetAuthenticator installs the decision function for UserName and Certificate
// identity tokens. Without one, every such token is rejected even when its auth
// mode is enabled, so enabling a mode never silently admits everyone.
func SetAuthenticator(a Authenticator) Option {
	return func(s *serverConfig) {
		s.authenticator = a
	}
}

// ClientCertificateValidator installs a check on the application instance
// certificate a client presents when it opens a secured channel. A non-nil
// error refuses the channel; a ua.StatusCode error is reported as that code.
// Without one, any well-formed RSA certificate is accepted.
func ClientCertificateValidator(v func(cert []byte) error) Option {
	return func(s *serverConfig) {
		s.clientCertValidator = v
	}
}

// identityResult carries what ActivateSession needs to know about an accepted token.
type identityResult struct {
	tokenType ua.UserTokenType
	policyID  string
	username  string
	// key names who the session is activated as, so a later activation can be
	// checked to be the same identity: "anonymous", "user:<name>" or
	// "cert:<thumbprint>".
	key string
}

// authenticateIdentity resolves the identity token of an ActivateSession
// request against the user token policies advertised for the channel's
// security policy and mode, then verifies and decides it.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.3
func (s *SessionService) authenticateIdentity(sc *uasc.SecureChannel, sess *session, req *ua.ActivateSessionRequest) (identityResult, ua.StatusCode) {
	var tokenValue any
	if req.UserIdentityToken != nil {
		tokenValue = req.UserIdentityToken.Value
	}

	// A null token is an anonymous token (Part 4, 5.6.3.2).
	var (
		tokenType ua.UserTokenType
		policyID  string
	)
	switch tok := tokenValue.(type) {
	case nil:
		tokenType = ua.UserTokenTypeAnonymous
	case *ua.AnonymousIdentityToken:
		tokenType, policyID = ua.UserTokenTypeAnonymous, tok.PolicyID
	case *ua.UserNameIdentityToken:
		tokenType, policyID = ua.UserTokenTypeUserName, tok.PolicyID
	case *ua.X509IdentityToken:
		tokenType, policyID = ua.UserTokenTypeCertificate, tok.PolicyID
	default:
		return identityResult{}, ua.StatusBadIdentityTokenInvalid
	}

	// One snapshot for the whole decision: policy, mode and certificate are
	// published together when the channel opens, never separately.
	peer := sc.PeerSecurity()

	policy, ok := s.matchTokenPolicy(peer, tokenType, policyID)
	if !ok {
		return identityResult{}, ua.StatusBadIdentityTokenInvalid
	}
	res := identityResult{tokenType: tokenType, policyID: policy.PolicyID}
	if tokenType == ua.UserTokenTypeAnonymous {
		res.key = "anonymous"
		return res, ua.StatusOK
	}

	if s.srv.cfg.authenticator == nil {
		s.warn("rejecting %s identity token from %s: no authenticator configured", tokenType, remoteAddr(sc))
		return identityResult{}, ua.StatusBadIdentityTokenRejected
	}

	// The token's own policy secures the secret; an empty one defers to the
	// channel's (Part 4, 7.41).
	tokenPolicyURI := policy.SecurityPolicyURI
	if tokenPolicyURI == "" {
		tokenPolicyURI = peer.PolicyURI
	}

	id := UserIdentity{
		TokenType:         tokenType,
		PolicyID:          policy.PolicyID,
		ClientCertificate: peer.Certificate,
		SecurityPolicyURI: peer.PolicyURI,
		SecurityMode:      peer.Mode,
		RemoteAddr:        remoteAddr(sc),
	}

	switch tok := tokenValue.(type) {
	case *ua.UserNameIdentityToken:
		password, code := s.decryptUserPassword(peer, sess, tokenPolicyURI, tok)
		if code != ua.StatusOK {
			return identityResult{}, code
		}
		id.Username = tok.UserName
		id.Password = password
		defer clear(password)
		res.username = tok.UserName
		res.key = "user:" + tok.UserName

	case *ua.X509IdentityToken:
		if code := s.verifyUserTokenSignature(sess, tokenPolicyURI, tok, req.UserTokenSignature); code != ua.StatusOK {
			return identityResult{}, code
		}
		id.Certificate = tok.CertificateData
		res.key = "cert:" + hex.EncodeToString(uapolicy.Thumbprint(tok.CertificateData))
		if cert, err := uapolicy.ParseCertificate(tok.CertificateData); err == nil {
			res.username = cert.Subject.String()
		}
	}

	if err := s.srv.cfg.authenticator(id); err != nil {
		var code ua.StatusCode
		if errors.As(err, &code) {
			return identityResult{}, code
		}
		return identityResult{}, ua.StatusBadUserAccessDenied
	}
	return res, ua.StatusOK
}

// matchTokenPolicy finds the advertised user token policy for the token, among
// the endpoints whose security policy and mode match the channel. An anonymous
// token with an empty policy ID matches any anonymous policy.
func (s *SessionService) matchTokenPolicy(peer uasc.PeerSecurity, tokenType ua.UserTokenType, policyID string) (*ua.UserTokenPolicy, bool) {
	chPolicy, chMode := peer.PolicyURI, peer.Mode
	if chPolicy == "" {
		chPolicy = ua.SecurityPolicyURINone
	}
	for _, ep := range s.srv.Endpoints() {
		if ep.SecurityPolicyURI != chPolicy || ep.SecurityMode != chMode {
			continue
		}
		for _, p := range ep.UserIdentityTokens {
			if p.TokenType != tokenType {
				continue
			}
			if p.PolicyID == policyID || (policyID == "" && tokenType == ua.UserTokenTypeAnonymous) {
				return p, true
			}
		}
	}
	return nil, false
}

// decryptUserPassword recovers the plaintext password of a UserName token.
// The secret is the legacy encrypted-secret layout of Part 4, 7.41.2.2:
// a little-endian uint32 length, the password, then the server nonce the
// client was last given.
func (s *SessionService) decryptUserPassword(peer uasc.PeerSecurity, sess *session, policyURI string, tok *ua.UserNameIdentityToken) ([]byte, ua.StatusCode) {
	if policyURI == ua.SecurityPolicyURINone {
		// A cleartext password is only acceptable inside an encrypted channel.
		if peer.Mode != ua.MessageSecurityModeSignAndEncrypt {
			return nil, ua.StatusBadIdentityTokenRejected
		}
		if tok.EncryptionAlgorithm != "" {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		return bytes.Clone(tok.Password), ua.StatusOK
	}

	if s.srv.cfg.privateKey == nil {
		s.warn("rejecting UserName token: server has no private key to decrypt it")
		return nil, ua.StatusBadIdentityTokenRejected
	}
	enc, err := uapolicy.Asymmetric(policyURI, s.srv.cfg.privateKey, nil)
	if err != nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	if tok.EncryptionAlgorithm != enc.EncryptionURI() {
		return nil, ua.StatusBadIdentityTokenInvalid
	}

	plain, err := enc.Decrypt(tok.Password)
	if err != nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	defer clear(plain)

	nonce := sess.serverNonce
	if len(plain) < 4 {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	n := binary.LittleEndian.Uint32(plain)
	if uint64(n) > uint64(len(plain)-4) || int(n) < len(nonce) {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	secret := plain[4 : 4+n]
	pwLen := len(secret) - len(nonce)
	if subtle.ConstantTimeCompare(secret[pwLen:], nonce) != 1 {
		// Wrong or replayed nonce: the token was not made for this activation.
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	return bytes.Clone(secret[:pwLen]), ua.StatusOK
}

// verifyUserTokenSignature checks that the client holds the private key of an
// X509 identity token's certificate: the signature covers the server
// certificate followed by the last server nonce (Part 4, 5.6.3.2).
func (s *SessionService) verifyUserTokenSignature(sess *session, policyURI string, tok *ua.X509IdentityToken, sig *ua.SignatureData) ua.StatusCode {
	if policyURI == ua.SecurityPolicyURINone || sig == nil || len(sig.Signature) == 0 {
		return ua.StatusBadUserSignatureInvalid
	}
	cert, err := uapolicy.ParseCertificate(tok.CertificateData)
	if err != nil {
		return ua.StatusBadIdentityTokenInvalid
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ua.StatusBadIdentityTokenInvalid
	}
	enc, err := uapolicy.Asymmetric(policyURI, nil, pub)
	if err != nil {
		return ua.StatusBadIdentityTokenInvalid
	}
	signed := append(bytes.Clone(s.srv.cfg.certificate), sess.serverNonce...)
	if err := enc.VerifySignature(signed, sig.Signature); err != nil {
		return ua.StatusBadUserSignatureInvalid
	}
	return ua.StatusOK
}

// sameLeafCertificate reports whether two DER blobs, each possibly a chain,
// carry the same leaf certificate.
func sameLeafCertificate(a, b []byte) bool {
	ca, err := uapolicy.ParseCertificate(a)
	if err != nil {
		return false
	}
	cb, err := uapolicy.ParseCertificate(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ca.Raw, cb.Raw)
}

func (s *SessionService) warn(msg string, args ...any) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Warn(msg, args...)
	}
}
