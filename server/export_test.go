package server

import (
	"sync/atomic"
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

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

// CountSecretCiphertext counts, until the test ends, the bytes of encrypted
// user token secret the server hands to its private key. Call it before
// starting the server.
func CountSecretCiphertext(t testing.TB) *atomic.Int64 {
	n := new(atomic.Int64)
	orig := decryptSecret
	decryptSecret = func(enc *uapolicy.EncryptionAlgorithm, b []byte) ([]byte, error) {
		n.Add(int64(len(b)))
		return orig(enc, b)
	}
	t.Cleanup(func() { decryptSecret = orig })
	return n
}
