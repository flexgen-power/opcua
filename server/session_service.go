package server

import (
	"crypto/rand"
	"log"
	"strings"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

const (
	sessionTimeoutMin     = 100 * time.Millisecond
	sessionTimeoutMax     = 1 * time.Hour
	sessionTimeoutDefault = 60 * time.Second

	sessionNonceLength = 32
)

// SessionService implements the Session Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6
type SessionService struct {
	srv *Server
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.2
func (s *SessionService) CreateSession(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.CreateSessionRequest](r)
	if err != nil {
		return nil, err
	}
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:           "create_session_request",
		ServiceType:     "CreateSession",
		RequestID:       reqID,
		SecureChannelID: secureChannelID(sc),
		RemoteAddr:      remoteAddr(sc),
		EndpointURL:     req.EndpointURL,
	})

	// On a secured channel the certificate in CreateSession must be the one
	// that opened the channel, or the session signature exchange proves
	// nothing about the channel's peer (Part 4, 5.6.2.2).
	if peer := sc.PeerSecurity(); peer.Mode != ua.MessageSecurityModeNone && !sameLeafCertificate(req.ClientCertificate, peer.Certificate) {
		s.warn("CreateSession from %s: client certificate does not match the secure channel certificate", remoteAddr(sc))
		return nil, ua.StatusBadSecurityChecksFailed
	}

	// New session
	sess := s.srv.sb.NewSession()
	sess.createChannelID = sc.ID()

	// Ensure session timeout is reasonable
	sess.cfg.sessionTimeout = time.Duration(req.RequestedSessionTimeout) * time.Millisecond
	if sess.cfg.sessionTimeout > sessionTimeoutMax || sess.cfg.sessionTimeout < sessionTimeoutMin {
		sess.cfg.sessionTimeout = sessionTimeoutDefault
	}

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}
	sess.serverNonce = nonce
	sess.remoteCertificate = req.ClientCertificate

	sig, alg, err := sc.NewSessionSignature(req.ClientCertificate, req.ClientNonce)
	if err != nil {
		log.Printf("error creating session signature")
		return nil, ua.StatusBadInternalError
	}

	matching_endpoints := make([]*ua.EndpointDescription, 0)
	reqTrimmedURL, _ := strings.CutSuffix(req.EndpointURL, "/")
	for i := range s.srv.endpoints {
		ep := s.srv.endpoints[i]
		epTrimmedURL, _ := strings.CutSuffix(ep.EndpointURL, "/")
		if epTrimmedURL == reqTrimmedURL {
			matching_endpoints = append(matching_endpoints, ep)
		}
	}

	response := &ua.CreateSessionResponse{
		ResponseHeader:        responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		SessionID:             sess.ID,
		AuthenticationToken:   sess.AuthTokenID,
		RevisedSessionTimeout: float64(sess.cfg.sessionTimeout / time.Millisecond),
		MaxRequestMessageSize: 0, // Not used
		ServerSignature: &ua.SignatureData{
			Signature: sig,
			Algorithm: alg,
		},
		ServerCertificate: s.srv.cfg.certificate,
		ServerNonce:       nonce,
		ServerEndpoints:   matching_endpoints,
	}
	matchedCount := len(matching_endpoints)
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:                "create_session_response",
		ServiceType:          "CreateSession",
		RequestID:            reqID,
		SecureChannelID:      secureChannelID(sc),
		RemoteAddr:           remoteAddr(sc),
		EndpointURL:          req.EndpointURL,
		MatchedEndpointCount: &matchedCount,
	})

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.3
func (s *SessionService) ActivateSession(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.ActivateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	peer := sc.PeerSecurity()
	transfer := sess.activated.Load() && sc.ID() != sess.channelID.Load()
	if !sess.activated.Load() {
		if sc.ID() != sess.createChannelID {
			return nil, ua.StatusBadSecureChannelIDInvalid
		}
	} else if transfer {
		if code := sess.checkTransferChannel(peer); code != ua.StatusOK {
			s.warn("ActivateSession from %s refused: session cannot move to this channel: %s", remoteAddr(sc), code)
			return nil, code
		}
	}

	if req.ClientSignature == nil {
		req.ClientSignature = &ua.SignatureData{}
	}
	err = sc.VerifySessionSignature(sess.remoteCertificate, sess.serverNonce, req.ClientSignature.Signature)
	if err != nil {
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Warn("error verifying session signature with nonce: %s", err)
		}
		return nil, ua.StatusBadSecurityChecksFailed
	}

	identity, code := s.authenticateIdentity(sc, sess, req)
	if code != ua.StatusOK {
		s.warn("ActivateSession from %s rejected: %s", remoteAddr(sc), code)
		return nil, code
	}
	if transfer {
		if code := sess.checkTransferIdentity(identity.key); code != ua.StatusOK {
			s.warn("ActivateSession from %s refused: session cannot move to a different identity: %s", remoteAddr(sc), code)
			return nil, code
		}
	}

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}
	sess.serverNonce = nonce
	sess.boundMode = peer.Mode
	sess.identity = identity.key
	sess.channelID.Store(sc.ID())
	sess.activated.Store(true)
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Info("session activated: remote=%s identity=%s policy=%s user=%q security=%s/%s",
			remoteAddr(sc), identity.tokenType, identity.policyID, identity.username,
			peer.PolicyURI, peer.Mode)
	}

	response := &ua.ActivateSessionResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		ServerNonce:    nonce,
		// Results:         []ua.StatusCode{},
		// DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.4
func (s *SessionService) CloseSession(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.CloseSessionRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.Session(req.RequestHeader)
	err = s.srv.sb.Close(req.RequestHeader.AuthenticationToken)
	if err != nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	if req.DeleteSubscriptions && sess != nil {
		s.srv.SubscriptionService.deleteSessionSubscriptions(sess)
	}

	response := &ua.CloseSessionResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.5
func (s *SessionService) Cancel(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.CancelRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}
