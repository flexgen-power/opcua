package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

type session struct {
	cfg sessionConfig

	ID                *ua.NodeID
	AuthTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte

	// createChannelID is the secure channel CreateSession arrived on; the
	// first ActivateSession must use the same one (Part 4, 5.6.3.1).
	createChannelID uint32
	// activated is set once ActivateSession accepts an identity, and
	// channelID is the channel the session is then bound to. Only an
	// activated session may call services, and only on its bound channel.
	activated atomic.Bool
	channelID atomic.Uint32

	// boundMode and identity record how the session was last activated: the
	// security mode of its channel and who it was activated as. Moving the
	// session to another channel has to keep both (Part 4, 5.6.3.1). Only
	// the request dispatcher touches them, and it handles one request at a
	// time.
	boundMode ua.MessageSecurityMode
	identity  string

	PublishRequests chan PubReq
}

type sessionConfig struct {
	sessionTimeout time.Duration
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s      map[string]*session
	logger Logger
}

func newSessionBroker(logger Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: logger,
	}
}

func (sb *sessionBroker) NewSession() *session {
	s := &session{
		ID: ua.NewGUIDNodeID(1, uuid.New().String()),
		// The token is what a session is looked up by. A 31-bit math/rand
		// number can be guessed; a random GUID cannot.
		AuthTokenID:     ua.NewGUIDNodeID(0, uuid.New().String()),
		PublishRequests: make(chan PubReq, 100),
	}

	sb.mu.Lock()
	sb.s[s.AuthTokenID.String()] = s
	sb.mu.Unlock()

	return s
}

func (sb *sessionBroker) Close(authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.s[authToken.String()] == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Close: error looking up session %v", authToken)
		}
		emitDiagWarn(sb.logger, diagPayload{
			Event:     "session_lookup_missing",
			ErrorText: authToken.String(),
		})
	}
	delete(sb.s, authToken.String())

	return nil
}

func (sb *sessionBroker) Session(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Session: error looking up session %v", authToken)
		}
		emitDiagWarn(sb.logger, diagPayload{
			Event:     "session_lookup_invalid",
			ErrorText: authToken.String(),
		})
	}

	return s
}

// checkTransferChannel decides, before the identity token is looked at, whether
// an activated session may move to the channel described by peer. A session
// that was activated over a secured channel stays on secured channels, and the
// client application certificate must be the one the session was created with,
// so an unencrypted or unauthenticated peer holding the session's token cannot
// take it over (Part 4, 5.6.3.1).
func (s *session) checkTransferChannel(peer uasc.PeerSecurity) ua.StatusCode {
	if s.boundMode == ua.MessageSecurityModeNone {
		return ua.StatusOK
	}
	if peer.Mode == ua.MessageSecurityModeNone {
		return ua.StatusBadSecurityChecksFailed
	}
	if !sameLeafCertificate(peer.Certificate, s.remoteCertificate) {
		return ua.StatusBadSecurityChecksFailed
	}
	return ua.StatusOK
}

// checkTransferIdentity requires that a session moved to another channel is
// activated as the same identity it already has. Changing the user of a
// session is allowed on its own channel, not by moving it.
func (s *session) checkTransferIdentity(key string) ua.StatusCode {
	if key != s.identity {
		return ua.StatusBadIdentityTokenRejected
	}
	return ua.StatusOK
}
