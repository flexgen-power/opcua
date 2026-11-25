// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
)

func TestServerChannelOpensOnlyUnderAnEnabledProfile(t *testing.T) {
	const (
		none    = ua.MessageSecurityModeNone
		sign    = ua.MessageSecurityModeSign
		encrypt = ua.MessageSecurityModeSignAndEncrypt
	)
	enabled := []SecurityProfile{{ua.SecurityPolicyURIBasic256Sha256, encrypt}}
	cases := []struct {
		name    string
		enabled []SecurityProfile
		policy  string
		mode    ua.MessageSecurityMode
		want    error
	}{
		{"enabled profile", enabled, ua.SecurityPolicyURIBasic256Sha256, encrypt, nil},
		{"None for discovery", enabled, ua.SecurityPolicyURINone, none, nil},
		{"None with nothing enabled", nil, ua.SecurityPolicyURINone, none, nil},
		{"other policy", enabled, ua.SecurityPolicyURIBasic256, encrypt, ua.StatusBadSecurityPolicyRejected},
		{"other policy, mode None", enabled, ua.SecurityPolicyURIBasic128Rsa15, none, ua.StatusBadSecurityPolicyRejected},
		{"unknown policy", enabled, "http://example.com/policy", encrypt, ua.StatusBadSecurityPolicyRejected},
		{"empty policy", enabled, "", none, ua.StatusBadSecurityPolicyRejected},
		{"nothing enabled", nil, ua.SecurityPolicyURIBasic256Sha256, encrypt, ua.StatusBadSecurityPolicyRejected},
		{"other mode", enabled, ua.SecurityPolicyURIBasic256Sha256, sign, ua.StatusBadSecurityModeRejected},
		{"enabled policy, mode None", enabled, ua.SecurityPolicyURIBasic256Sha256, none, ua.StatusBadSecurityModeRejected},
		{"enabled policy, invalid mode", enabled, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeInvalid, ua.StatusBadSecurityModeRejected},
		{"None policy, secured mode", enabled, ua.SecurityPolicyURINone, encrypt, ua.StatusBadSecurityModeRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecureChannel{kind: server, cfg: &Config{EnabledSecurity: tc.enabled}}
			err := s.checkOpenPolicy(tc.policy)
			if err == nil {
				// The mode is checked against the policy the channel took
				// from the message header.
				s.cfg.SecurityPolicyURI = tc.policy
				err = s.checkOpenMode(tc.mode)
			}
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.want, err)
			}
		})
	}
}
