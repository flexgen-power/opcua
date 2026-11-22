package server_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

// A requested session timeout in range is honoured in whole milliseconds and
// anything else gets the 60 s default. A request too large for a
// time.Duration used to wrap into range, so 18446744074710 ms became a
// session the reaper closed after about a second.
func TestCreateSessionRevisesTheRequestedTimeout(t *testing.T) {
	ss := startSecureServer(t,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeNone)

	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	defer c.Close(ctx)

	const def = 60000
	for _, tc := range []struct {
		name      string
		requested float64
		want      float64
	}{
		{"normal", 30000, 30000},
		{"lower bound", 100, 100},
		{"lower bound less a fraction", 99.9, def},
		{"upper bound", 3600000, 3600000},
		{"upper bound plus a fraction", 3600000.5, 3600000},
		{"above upper bound", 3600001, def},
		{"zero", 0, def},
		{"negative", -1000, def},
		{"NaN", math.NaN(), def},
		{"+Inf", math.Inf(1), def},
		{"-Inf", math.Inf(-1), def},
		{"wraps time.Duration", 18446744074710, def},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := sendFor(ctx, c.SecureChannel(), &ua.CreateSessionRequest{
				ClientDescription:       &ua.ApplicationDescription{ApplicationType: ua.ApplicationTypeClient, ApplicationName: &ua.LocalizedText{}},
				EndpointURL:             ss.addr,
				SessionName:             tc.name,
				ClientNonce:             make([]byte, 32),
				RequestedSessionTimeout: tc.requested,
			}, nil, 5*time.Second)
			require.NoError(t, err)
			require.Equal(t, tc.want, r.(*ua.CreateSessionResponse).RevisedSessionTimeout)
		})
	}
}
