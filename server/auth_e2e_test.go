// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

// These tests drive the gopcua client against the server over real sockets,
// pinning the security profile a customer-facing deployment depends on:
// Basic256Sha256 SignAndEncrypt, UserName authentication decided by an
// Authenticator, and subscriptions delivering over the encrypted channel.

func genCert(t *testing.T, appURI string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u, err := url.Parse(appURI)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: appURI},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der, key
}

// freePort asks the kernel for an unused TCP port so parallel packages do not collide.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type secureServer struct {
	srv      *server.Server
	addr     string
	node     *server.Node
	soc      atomic.Value // float64, read by the node's ValueFunc
	authHits atomic.Int32
}

const (
	testUser     = "scada"
	testPassword = "correct horse battery staple"
)

// startSecureServer runs a server offering only Basic256Sha256/SignAndEncrypt
// with UserName auth, plus any extra options a test needs.
func startSecureServer(t *testing.T, extra ...server.Option) *secureServer {
	t.Helper()
	cert, key := genCert(t, "urn:gopcua:test:server")
	port := freePort(t)
	ss := &secureServer{addr: fmt.Sprintf("opc.tcp://localhost:%d", port)}

	opts := []server.Option{
		server.EndPoint("localhost", port),
		server.PrivateKey(key),
		server.Certificate(cert),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.SetAuthenticator(func(id server.UserIdentity) error {
			ss.authHits.Add(1)
			if id.TokenType == ua.UserTokenTypeUserName && id.Username == testUser && string(id.Password) == testPassword {
				return nil
			}
			return errors.New("bad credentials")
		}),
	}
	ss.srv = server.New(append(opts, extra...)...)

	nodeNS := server.NewNodeNameSpace(ss.srv, "auth-test")
	root, err := ss.srv.Namespace(0)
	require.NoError(t, err)
	root.Objects().AddRef(nodeNS.Objects(), id.HasComponent, true)
	// A ValueFunc rather than Node.SetAttribute: the node's attribute map is
	// not safe to write while the server serves reads, which is also why the
	// interface publishes this way.
	ss.soc.Store(float64(50))
	ss.node = nodeNS.AddNode(server.NewVariableNode(ua.NewStringNodeID(nodeNS.ID(), "soc"), "soc",
		server.ValueFunc(func() *ua.DataValue { return server.DataValueFromValue(ss.soc.Load()) })))
	nodeNS.Objects().AddRef(ss.node, id.HasComponent, true)

	require.NoError(t, ss.srv.Start(context.Background()))
	t.Cleanup(func() { _ = ss.srv.Close() })
	return ss
}

func endpointFor(t *testing.T, ctx context.Context, addr string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	var (
		eps []*ua.EndpointDescription
		err error
	)
	for {
		if eps, err = opcua.GetEndpoints(ctx, addr); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			require.NoError(t, err, "server never became ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, e := range eps {
		if e.SecurityMode == mode {
			return e
		}
	}
	t.Fatalf("no endpoint with mode %s", mode)
	return nil
}

func secureClient(t *testing.T, ctx context.Context, ss *secureServer, auth ua.UserTokenType, extra ...opcua.Option) *opcua.Client {
	t.Helper()
	ep := endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeSignAndEncrypt)
	cert, key := genCert(t, "urn:gopcua:test:client")
	opts := append([]opcua.Option{
		opcua.Certificate(cert),
		opcua.PrivateKey(key),
		opcua.AutoReconnect(false),
	}, extra...)
	opts = append(opts, opcua.SecurityFromEndpoint(ep, auth))
	c, err := opcua.NewClient(ss.addr, opts...)
	require.NoError(t, err)
	return c
}

func requireStatus(t *testing.T, err error, want ua.StatusCode) {
	t.Helper()
	require.Error(t, err)
	var got ua.StatusCode
	require.True(t, errors.As(err, &got), "error %v carries no status code", err)
	require.Equal(t, want, got)
}

func TestUserNameOverSignAndEncryptReadsAndSubscribes(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	require.NoError(t, c.Connect(ctx))
	defer c.Close(ctx)
	require.EqualValues(t, 1, ss.authHits.Load(), "authenticator should decide the login exactly once")

	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)
	require.Equal(t, float64(50), resp.Results[0].Value.Value())

	notifs := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, notifs)
	require.NoError(t, err)
	defer sub.Cancel(ctx)
	mres, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(ss.node.ID(), ua.AttributeIDValue, 7))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, mres.Results[0].StatusCode)

	// The update is published on the encrypted channel, so receiving it proves
	// MonitoredItem delivery works under SignAndEncrypt, not only Read.
	ss.soc.Store(float64(73.5))
	ss.srv.ChangeNotification(ss.node.ID())

	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-notifs:
			require.NoError(t, n.Error)
			dc, ok := n.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range dc.MonitoredItems {
				if item.ClientHandle == 7 && item.Value.Value.Value() == float64(73.5) {
					return
				}
			}
		case <-deadline:
			t.Fatal("no data change notification for the updated value")
		}
	}
}

func TestWrongPasswordIsDenied(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, "wrong"))
	requireStatus(t, c.Connect(ctx), ua.StatusBadUserAccessDenied)
	require.EqualValues(t, 1, ss.authHits.Load())
}

func TestAnonymousRejectedWhenNotEnabled(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The endpoint advertises no anonymous policy, so the client falls back to
	// its default anonymous token, which matches nothing the server offers.
	c := secureClient(t, ctx, ss, ua.UserTokenTypeAnonymous)
	requireStatus(t, c.Connect(ctx), ua.StatusBadIdentityTokenInvalid)
	require.EqualValues(t, 0, ss.authHits.Load(), "an unknown token must not reach the authenticator")
}

func TestNoneChannelCannotActivate(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeSignAndEncrypt) // wait for readiness

	// The server still accepts a None OpenSecureChannel at the transport
	// layer, but with no None endpoint advertised no identity can activate.
	for _, auth := range []opcua.Option{opcua.AuthAnonymous(), opcua.AuthUsername(testUser, testPassword)} {
		c, err := opcua.NewClient(ss.addr,
			opcua.SecurityMode(ua.MessageSecurityModeNone),
			opcua.SecurityPolicy("None"),
			opcua.AutoReconnect(false),
			auth,
		)
		require.NoError(t, err)
		requireStatus(t, c.Connect(ctx), ua.StatusBadIdentityTokenInvalid)
	}
	require.EqualValues(t, 0, ss.authHits.Load())
}

func TestUserNameRejectedWithoutAuthenticator(t *testing.T) {
	// Enabling UserName without an Authenticator must fail closed.
	cert, key := genCert(t, "urn:gopcua:test:server")
	port := freePort(t)
	srv := server.New(
		server.EndPoint("localhost", port),
		server.PrivateKey(key),
		server.Certificate(cert),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
	)
	require.NoError(t, srv.Start(context.Background()))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ss := &secureServer{srv: srv, addr: fmt.Sprintf("opc.tcp://localhost:%d", port)}
	c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	requireStatus(t, c.Connect(ctx), ua.StatusBadIdentityTokenRejected)
}

func TestClientCertificateValidatorRefusesChannel(t *testing.T) {
	var seen atomic.Int32
	ss := startSecureServer(t, server.ClientCertificateValidator(func(cert []byte) error {
		seen.Add(1)
		return ua.StatusBadCertificateUntrusted
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	require.Error(t, c.Connect(ctx))
	require.Positive(t, seen.Load(), "validator was not consulted")
	require.EqualValues(t, 0, ss.authHits.Load())
}

func TestServicesRequireActivatedSession(t *testing.T) {
	// A None/anonymous server keeps the transport simple; the gate is the
	// same whatever the security profile.
	port := freePort(t)
	srv := server.New(
		server.EndPoint("localhost", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, srv.Start(context.Background()))
	defer srv.Close()
	addr := fmt.Sprintf("opc.tcp://localhost:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpointFor(t, ctx, addr, ua.MessageSecurityModeNone)

	c, err := opcua.NewClient(addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	defer c.Close(ctx)
	sc := c.SecureChannel()

	send := func(req ua.Request, token *ua.NodeID) (ua.Response, error) {
		var out ua.Response
		err := sc.SendRequest(ctx, req, token, func(r ua.Response) error {
			out = r
			return nil
		})
		return out, err
	}
	// Raw requests bypass the client's helpers, so every pointer field the
	// encoder walks has to be set explicitly.
	read := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{
		NodeID:       ua.NewNumericNodeID(0, id.Server_ServerStatus_State),
		AttributeID:  ua.AttributeIDValue,
		DataEncoding: &ua.QualifiedName{},
	}}}

	// No session at all.
	_, err = send(read, nil)
	requireStatus(t, err, ua.StatusBadSessionIDInvalid)

	// A created but never activated session.
	r, err := send(&ua.CreateSessionRequest{
		ClientDescription:       &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, ApplicationName: &ua.LocalizedText{}},
		EndpointURL:             addr,
		SessionName:             "gate",
		ClientNonce:             make([]byte, 32),
		RequestedSessionTimeout: 60000,
	}, nil)
	require.NoError(t, err)
	token := r.(*ua.CreateSessionResponse).AuthenticationToken

	_, err = send(read, token)
	requireStatus(t, err, ua.StatusBadSessionNotActivated)
	_, err = send(&ua.CreateSubscriptionRequest{RequestedPublishingInterval: 100, RequestedLifetimeCount: 60, RequestedMaxKeepAliveCount: 10, PublishingEnabled: true}, token)
	requireStatus(t, err, ua.StatusBadSessionNotActivated)

	// Activating it opens the gate.
	_, err = send(&ua.ActivateSessionRequest{
		ClientSignature:    &ua.SignatureData{},
		UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
		UserTokenSignature: &ua.SignatureData{},
	}, token)
	require.NoError(t, err)
	r, err = send(read, token)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, r.(*ua.ReadResponse).Results[0].Status)
}
