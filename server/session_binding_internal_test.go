package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

func TestSessionTransferRules(t *testing.T) {
	secured := func(t *testing.T, appCert []byte) *session {
		return &session{remoteCertificate: appCert, boundMode: ua.MessageSecurityModeSignAndEncrypt, identity: "user:scada"}
	}
	a := mustCert(t, "urn:test:a")
	b := mustCert(t, "urn:test:b")
	peer := func(mode ua.MessageSecurityMode, c []byte) uasc.PeerSecurity {
		return uasc.PeerSecurity{Mode: mode, Certificate: c}
	}

	t.Run("secured session to the same certificate", func(t *testing.T) {
		require.Equal(t, ua.StatusOK, secured(t, a).checkTransferChannel(peer(ua.MessageSecurityModeSignAndEncrypt, a)))
	})
	t.Run("secured session to an unencrypted channel", func(t *testing.T) {
		require.Equal(t, ua.StatusBadSecurityChecksFailed, secured(t, a).checkTransferChannel(peer(ua.MessageSecurityModeNone, nil)))
	})
	t.Run("secured session to another certificate", func(t *testing.T) {
		require.Equal(t, ua.StatusBadSecurityChecksFailed, secured(t, a).checkTransferChannel(peer(ua.MessageSecurityModeSignAndEncrypt, b)))
	})
	t.Run("secured session to a Sign channel with the same certificate", func(t *testing.T) {
		// Mode is not required to match: only that the channel is secured by
		// the application the session was created with.
		require.Equal(t, ua.StatusOK, secured(t, a).checkTransferChannel(peer(ua.MessageSecurityModeSign, a)))
	})
	t.Run("session on a None channel may move to any channel", func(t *testing.T) {
		s := &session{boundMode: ua.MessageSecurityModeNone, identity: "anonymous"}
		require.Equal(t, ua.StatusOK, s.checkTransferChannel(peer(ua.MessageSecurityModeNone, nil)))
		require.Equal(t, ua.StatusOK, s.checkTransferChannel(peer(ua.MessageSecurityModeSignAndEncrypt, a)))
	})

	t.Run("identity must be unchanged", func(t *testing.T) {
		s := secured(t, a)
		require.Equal(t, ua.StatusOK, s.checkTransferIdentity("user:scada"))
		require.Equal(t, ua.StatusBadIdentityTokenRejected, s.checkTransferIdentity("user:other"))
		require.Equal(t, ua.StatusBadIdentityTokenRejected, s.checkTransferIdentity("anonymous"),
			"a session cannot be downgraded to anonymous by moving it")
		require.Equal(t, ua.StatusBadIdentityTokenRejected, s.checkTransferIdentity(""))
	})
}

func TestSessionTokensAreRandomGUIDs(t *testing.T) {
	sb := newSessionBroker(nil)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := sb.NewSession().AuthTokenID
		require.Equal(t, ua.NodeIDTypeGUID, tok.Type(), "a 32-bit numeric token can be guessed")
		require.False(t, seen[tok.String()], "token repeated")
		seen[tok.String()] = true
	}
}
