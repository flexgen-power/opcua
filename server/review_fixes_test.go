// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

// sendFor sends req on sc and returns the response the channel delivered,
// ServiceFaults included, together with the error.
func sendFor(ctx context.Context, sc *uasc.SecureChannel, req ua.Request, token *ua.NodeID, timeout time.Duration) (ua.Response, error) {
	var out ua.Response
	err := sc.SendRequestWithTimeout(ctx, req, token, timeout, func(r ua.Response) error {
		out = r
		return nil
	})
	return out, err
}

func ecdsaCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// A session created over None keeps whatever certificate the client sent.
// Moving it to a secured channel checks the session signature against that
// certificate, which used to assume an RSA key and panic the request
// dispatcher, ending the process. It must be refused instead.
func TestSessionTransferWithANonRSACertificateIsRefused(t *testing.T) {
	ss := startSecureServer(t,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeNone)

	peer, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, peer.Dial(ctx))
	defer peer.Close(ctx)

	r, err := sendFor(ctx, peer.SecureChannel(), &ua.CreateSessionRequest{
		ClientDescription:       &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, ApplicationName: &ua.LocalizedText{}},
		EndpointURL:             ss.addr,
		SessionName:             "ecdsa",
		ClientNonce:             make([]byte, 32),
		ClientCertificate:       ecdsaCert(t),
		RequestedSessionTimeout: 60000,
	}, nil, 5*time.Second)
	require.NoError(t, err)
	token := r.(*ua.CreateSessionResponse).AuthenticationToken
	_, err = sendFor(ctx, peer.SecureChannel(), &ua.ActivateSessionRequest{
		ClientSignature:    &ua.SignatureData{},
		UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
		UserTokenSignature: &ua.SignatureData{},
	}, token, 5*time.Second)
	require.NoError(t, err)

	secured, _ := openRawChannel(t, ctx, ss)
	_, err = sendFor(ctx, secured, &ua.ActivateSessionRequest{
		ClientSignature:    &ua.SignatureData{},
		UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
		UserTokenSignature: &ua.SignatureData{},
	}, token, 5*time.Second)
	requireStatus(t, err, ua.StatusBadSecurityChecksFailed)

	_, err = opcua.GetEndpoints(ctx, ss.addr)
	require.NoError(t, err, "the server stopped serving")
}

// A refusal is sent as a ServiceFault that echoes the request's handle, so a
// client matching responses on it sees the refusal, not a stray response.
func TestFaultCarriesTheRequestHandle(t *testing.T) {
	ss := startSecureServer(t,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeNone)

	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	defer c.Close(ctx)

	read := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{
		NodeID:       ua.NewNumericNodeID(0, id.Server_ServerStatus_State),
		AttributeID:  ua.AttributeIDValue,
		DataEncoding: &ua.QualifiedName{},
	}}}
	r, err := sendFor(ctx, c.SecureChannel(), read, nil, 5*time.Second)
	requireStatus(t, err, ua.StatusBadSessionIDInvalid)
	fault, ok := r.(*ua.ServiceFault)
	require.True(t, ok, "got %T, want a ServiceFault", r)
	require.NotZero(t, read.RequestHeader.RequestHandle)
	require.Equal(t, read.RequestHeader.RequestHandle, fault.ResponseHeader.RequestHandle)
}

// Any non-nil error from an Authenticator refuses the login. A Good or
// Uncertain status code returned as an error is not a refusal the client can
// be told as is, and StatusOK returned as an error used to admit the client
// with an empty identity.
func TestAuthenticatorErrorThatIsNotBadStillRefuses(t *testing.T) {
	for _, code := range []ua.StatusCode{ua.StatusOK, ua.StatusUncertain, ua.StatusGoodClamped} {
		t.Run(code.Error(), func(t *testing.T) {
			ss := startSecureServer(t, server.SetAuthenticator(func(server.UserIdentity) error { return code }))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
			requireStatus(t, c.Connect(ctx), ua.StatusBadUserAccessDenied)
		})
	}
}

// One goroutine dispatches every client's requests, so a panic in a service
// handler must become a fault for that request, not end the process.
func TestPanickingHandlerBecomesAFault(t *testing.T) {
	ss := startSecureServer(t, server.SetAuthenticator(func(id server.UserIdentity) error {
		if id.Username == "boom" {
			panic("authenticator bug")
		}
		if id.Username == testUser && string(id.Password) == testPassword {
			return nil
		}
		return errors.New("bad credentials")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername("boom", "x"))
	requireStatus(t, c.Connect(ctx), ua.StatusBadInternalError)

	ok := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	require.NoError(t, ok.Connect(ctx), "the server stopped serving after the panic")
	defer ok.Close(ctx)
	readSoc(t, ctx, ok, ss)
}

// After a session moves to a new channel, a Publish sent there is answered
// there. Responses used to go to the channel the subscription was created
// on, so a reconnected client got no data until it recreated its
// subscriptions.
func TestPublishIsAnsweredOnTheChannelItArrivedOn(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cert, key := genCert(t, "urn:gopcua:test:owner")
	owner := func() *opcua.Client {
		return secureClient(t, ctx, ss, ua.UserTokenTypeUserName,
			opcua.AuthUsername(testUser, testPassword), opcua.Certificate(cert), opcua.PrivateKey(key))
	}
	first := owner()
	require.NoError(t, first.Connect(ctx))
	defer first.Close(ctx)
	r, err := sendFor(ctx, first.SecureChannel(), &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 50,
		RequestedLifetimeCount:      600,
		RequestedMaxKeepAliveCount:  2,
		PublishingEnabled:           true,
	}, ss.srv.ActivatedSessionTokens()[0], 5*time.Second)
	require.NoError(t, err)
	subID := r.(*ua.CreateSubscriptionResponse).SubscriptionID

	sess, err := first.DetachSession(ctx)
	require.NoError(t, err)
	next := owner()
	require.NoError(t, next.Dial(ctx))
	defer next.Close(ctx)
	require.NoError(t, next.ActivateSession(ctx, sess))

	r, err = sendFor(ctx, next.SecureChannel(), &ua.PublishRequest{
		SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
	}, ss.srv.ActivatedSessionTokens()[0], 10*time.Second)
	require.NoError(t, err, "no Publish response on the session's new channel")
	require.Equal(t, subID, r.(*ua.PublishResponse).SubscriptionID)
}
