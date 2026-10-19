package server

import "github.com/gopcua/opcua/ua"

// ActivatedSessionTokens returns the authentication tokens of the sessions that
// have been activated. A test uses one to act as a peer that has somehow
// learned another client's token, which is the situation channel binding is
// there to make harmless.
func (s *Server) ActivatedSessionTokens() []*ua.NodeID {
	s.sb.mu.Lock()
	defer s.sb.mu.Unlock()
	var out []*ua.NodeID
	for _, sess := range s.sb.s {
		if sess.activated.Load() {
			out = append(out, sess.AuthTokenID)
		}
	}
	return out
}
