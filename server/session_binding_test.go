// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

func readSoc(t *testing.T, ctx context.Context, c *opcua.Client, ss *secureServer) {
	t.Helper()
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)
}

// sendWithToken sends a request on c's channel carrying another session's token.
func sendWithToken(ctx context.Context, c *opcua.Client, req ua.Request, token *ua.NodeID) error {
	return c.SecureChannel().SendRequest(ctx, req, token, func(ua.Response) error { return nil })
}

// A session is bound to the channel it was activated on. Holding its token on
// another channel does not let a peer close it, or use it.
func TestCloseSessionNeedsTheSessionsChannel(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	victim := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	require.NoError(t, victim.Connect(ctx))
	tokens := ss.srv.ActivatedSessionTokens()
	require.Len(t, tokens, 1)

	// A second channel with no session of its own.
	peer := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
	require.NoError(t, peer.Dial(ctx))
	defer peer.Close(ctx)

	requireStatus(t, sendWithToken(ctx, peer, &ua.CloseSessionRequest{DeleteSubscriptions: true}, tokens[0]), ua.StatusBadSecureChannelIDInvalid)
	requireStatus(t, sendWithToken(ctx, peer, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue, DataEncoding: &ua.QualifiedName{}},
	}}, tokens[0]), ua.StatusBadSecureChannelIDInvalid)

	require.Len(t, ss.srv.ActivatedSessionTokens(), 1, "the session was closed from another channel")
	readSoc(t, ctx, victim, ss)

	// Its own channel can still close it.
	require.NoError(t, victim.Close(ctx))
	require.Eventually(t, func() bool { return len(ss.srv.ActivatedSessionTokens()) == 0 }, 5*time.Second, 20*time.Millisecond)
}

// Moving a session to another channel needs the client application certificate
// it was created with and, over a secured channel, keeps it secured (Part 4,
// 5.6.3.1). Without that, anyone who learned a session's token could take it
// over, and an unencrypted channel could carry a session that was encrypted.
func TestSessionTransferNeedsTheSameClientAndAChannelAsSecure(t *testing.T) {
	// The None endpoint is the case that matters: it is what a transition
	// deployment leaves enabled beside the secured one.
	ss := startSecureServer(t,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cert, key := genCert(t, "urn:gopcua:test:owner")
	owner := func() *opcua.Client {
		return secureClient(t, ctx, ss, ua.UserTokenTypeUserName,
			opcua.AuthUsername(testUser, testPassword), opcua.Certificate(cert), opcua.PrivateKey(key))
	}
	victim := owner()
	require.NoError(t, victim.Connect(ctx))
	tokens := ss.srv.ActivatedSessionTokens()
	require.Len(t, tokens, 1)
	token := tokens[0]

	t.Run("an anonymous peer on an unencrypted channel cannot take it", func(t *testing.T) {
		peer, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
		require.NoError(t, err)
		require.NoError(t, peer.Dial(ctx))
		defer peer.Close(ctx)

		requireStatus(t, sendWithToken(ctx, peer, &ua.ActivateSessionRequest{
			ClientSignature:    &ua.SignatureData{},
			UserIdentityToken:  ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
			UserTokenSignature: &ua.SignatureData{},
		}, token), ua.StatusBadSecurityChecksFailed)
		requireStatus(t, sendWithToken(ctx, peer, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
			{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue, DataEncoding: &ua.QualifiedName{}},
		}}, token), ua.StatusBadSecureChannelIDInvalid)
		readSoc(t, ctx, victim, ss)
	})

	sess, err := victim.DetachSession(ctx)
	require.NoError(t, err)
	require.NotNil(t, sess)

	t.Run("another application certificate cannot take it", func(t *testing.T) {
		other := secureClient(t, ctx, ss, ua.UserTokenTypeUserName, opcua.AuthUsername(testUser, testPassword))
		require.NoError(t, other.Dial(ctx))
		defer other.Close(ctx)
		requireStatus(t, other.ActivateSession(ctx, sess), ua.StatusBadSecurityChecksFailed)
	})

	t.Run("the same application can move it, and the old channel is refused", func(t *testing.T) {
		next := owner()
		require.NoError(t, next.Dial(ctx))
		defer next.Close(ctx)
		require.NoError(t, next.ActivateSession(ctx, sess))
		readSoc(t, ctx, next, ss)

		// Once the new channel is accepted the old one is refused (Part 4, 5.6.3.1).
		requireStatus(t, sendWithToken(ctx, victim, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
			{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue, DataEncoding: &ua.QualifiedName{}},
		}}, token), ua.StatusBadSecureChannelIDInvalid)
	})
}
