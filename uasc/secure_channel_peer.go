// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"bytes"
	"slices"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

// PeerSecurity is the security profile a server channel was opened with: the
// policy and mode the client asked for in its OpenSecureChannel, and the
// application certificate it presented.
//
// The profile is fixed when the channel is first opened. A renewal that asks
// for a different policy, mode or certificate is refused rather than applied,
// so a service that checked the profile once, such as an ActivateSession that
// decided which identity tokens are acceptable, can rely on it for the life of
// the channel.
type PeerSecurity struct {
	PolicyURI string
	Mode      ua.MessageSecurityMode
	// Certificate is the peer's DER certificate, possibly a chain, or nil on a
	// None channel.
	Certificate []byte
}

// SecurityProfile is a security policy together with a message security mode.
type SecurityProfile struct {
	PolicyURI string
	Mode      ua.MessageSecurityMode
}

// PeerSecurity returns the channel's security profile. It is published whole,
// so the three fields always belong together, and it is safe to call from any
// goroutine. Before the channel has opened it reports the None profile.
func (s *SecureChannel) PeerSecurity() PeerSecurity {
	if p := s.peer.Load(); p != nil {
		return *p
	}
	return PeerSecurity{PolicyURI: ua.SecurityPolicyURINone, Mode: ua.MessageSecurityModeNone}
}

// established reports whether a server channel has completed its first
// OpenSecureChannel, so that a further one is a renewal.
func (s *SecureChannel) established() bool {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	return s.activeInstance != nil
}

// checkOpenPolicy refuses an OpenSecureChannel that would open a server channel
// under a security policy the server has not enabled. The policy is in the
// clear in the message header, so this runs before the peer's certificate is
// looked at and before the private key is used: the key only ever works under
// a policy the server offers. Policy None is let through for discovery.
func (s *SecureChannel) checkOpenPolicy(policyURI string) error {
	if policyURI == ua.SecurityPolicyURINone {
		return nil
	}
	for _, p := range s.cfg.EnabledSecurity {
		if p.PolicyURI == policyURI {
			return nil
		}
	}
	return ua.StatusBadSecurityPolicyRejected
}

// checkOpenMode refuses an OpenSecureChannel that would open a server channel
// in a security mode the server has not enabled for the channel's policy.
func (s *SecureChannel) checkOpenMode(mode ua.MessageSecurityMode) error {
	policyURI := s.cfg.SecurityPolicyURI
	if policyURI == ua.SecurityPolicyURINone && mode == ua.MessageSecurityModeNone {
		return nil
	}
	if slices.Contains(s.cfg.EnabledSecurity, SecurityProfile{PolicyURI: policyURI, Mode: mode}) {
		return nil
	}
	return ua.StatusBadSecurityModeRejected
}

// checkRenewalPolicy refuses an OpenSecureChannel on an established channel
// that asks for another security policy or comes from another application
// certificate. Called before anything on the channel is changed.
func (s *SecureChannel) checkRenewalPolicy(policyURI string, senderCert []byte) error {
	if policyURI != s.cfg.SecurityPolicyURI {
		return ua.StatusBadSecurityPolicyRejected
	}
	if policyURI == ua.SecurityPolicyURINone {
		return nil
	}
	if !sameLeafCertificate(senderCert, s.cfg.RemoteCertificate) {
		return ua.StatusBadSecurityChecksFailed
	}
	return nil
}

// checkRenewalMode refuses a renewal that asks for another security mode.
func (s *SecureChannel) checkRenewalMode(req *ua.OpenSecureChannelRequest) error {
	if req.RequestType != ua.SecurityTokenRequestTypeRenew {
		return ua.StatusBadRequestTypeInvalid
	}
	if req.SecurityMode != s.cfg.SecurityMode {
		return ua.StatusBadSecurityModeRejected
	}
	return nil
}

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
