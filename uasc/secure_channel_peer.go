// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import "github.com/gopcua/opcua/ua"

// SecurityPolicyURI returns the security policy negotiated by the most recent
// OpenSecureChannel on this channel.
func (s *SecureChannel) SecurityPolicyURI() string {
	return s.cfg.SecurityPolicyURI
}

// SecurityMode returns the message security mode negotiated by the most
// recent OpenSecureChannel on this channel.
func (s *SecureChannel) SecurityMode() ua.MessageSecurityMode {
	return s.cfg.SecurityMode
}

// RemoteCertificate returns the DER certificate (possibly a chain) the peer
// presented in its OpenSecureChannel request, or nil on a None channel.
func (s *SecureChannel) RemoteCertificate() []byte {
	return s.cfg.RemoteCertificate
}
