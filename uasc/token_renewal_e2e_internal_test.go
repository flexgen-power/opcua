package uasc

import (
	"context"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// renewalPair is a client and a server SecureChannel connected over loopback
// with Basic256Sha256 and a one hour token lifetime. The server answers every
// ReadRequest.
type renewalPair struct {
	ctx context.Context
	cli *SecureChannel
	srv *SecureChannel
	// srvErr receives the error that ended the server's receive loop.
	srvErr chan error
}

func newRenewalPair(t *testing.T, mode ua.MessageSecurityMode) *renewalPair {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	srvCert, srvKey := genThumbprintTestCert(t, "renewal server")
	cliCert, cliKey := genThumbprintTestCert(t, "renewal client")

	ln, err := uacp.Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	endpoint := "opc.tcp://" + ln.Addr().String()

	p := &renewalPair{ctx: ctx, srvErr: make(chan error, 1)}
	srvCh := make(chan *SecureChannel, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			close(srvCh)
			return
		}
		srv, err := NewServerSecureChannel(endpoint, conn, &Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      mode,
			LocalKey:          srvKey,
			Certificate:       srvCert,
		}, make(chan error, 8), 1, 1, 1)
		if err != nil {
			conn.Close()
			close(srvCh)
			return
		}
		srvCh <- srv
		for {
			msg := srv.Receive(ctx)
			if msg.Err != nil {
				p.srvErr <- msg.Err
				return
			}
			if _, ok := msg.Request().(*ua.ReadRequest); ok {
				_ = srv.SendResponseWithContext(ctx, msg.RequestID, &ua.ReadResponse{
					ResponseHeader: &ua.ResponseHeader{
						Timestamp:          time.Now(),
						ServiceDiagnostics: &ua.DiagnosticInfo{},
						StringTable:        []string{},
						AdditionalHeader:   ua.NewExtensionObject(nil),
					},
				})
			}
		}
	}()

	conn, err := uacp.Dial(ctx, endpoint)
	require.NoError(t, err)
	p.cli, err = NewSecureChannel(endpoint, conn, &Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      mode,
		Certificate:       cliCert,
		LocalKey:          cliKey,
		RemoteCertificate: srvCert,
		Thumbprint:        uapolicy.Thumbprint(srvCert),
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    5 * time.Second,
	}, make(chan error, 8))
	require.NoError(t, err)
	t.Cleanup(func() { p.cli.Close() })
	require.NoError(t, p.cli.Open(ctx))

	srv, ok := <-srvCh
	require.True(t, ok, "server channel was not created")
	t.Cleanup(func() { srv.Close() })
	p.srv = srv
	return p
}

// read sends a ReadRequest secured with inst, or with the client's active
// instance if inst is nil, and requires a ReadResponse.
func (p *renewalPair) read(t *testing.T, inst *channelInstance) {
	t.Helper()
	h := func(v ua.Response) error {
		_, ok := v.(*ua.ReadResponse)
		require.True(t, ok, "got %T", v)
		return nil
	}
	var err error
	if inst == nil {
		err = p.cli.SendRequest(p.ctx, &ua.ReadRequest{}, nil, h)
	} else {
		err = p.cli.sendRequestWithTimeout(p.ctx, &ua.ReadRequest{}, p.cli.nextRequestID(), inst, nil, 3*time.Second, h, nil)
	}
	select {
	case srvErr := <-p.srvErr:
		t.Fatalf("server stopped receiving: %v", srvErr)
	default:
	}
	require.NoError(t, err)
}

// serverInstance returns the server's active channel instance.
func (p *renewalPair) serverInstance(t *testing.T) *channelInstance {
	t.Helper()
	inst, err := p.srv.getActiveChannelInstance()
	require.NoError(t, err)
	return inst
}

// serverOutgoing returns the token ID the server secures its next message with.
func (p *renewalPair) serverOutgoing(t *testing.T) uint32 {
	t.Helper()
	inst := p.serverInstance(t)
	inst.Lock()
	defer inst.Unlock()
	return inst.outgoingTokenID()
}

// A client that keeps sending with its old token after a renewal must keep
// getting responses under the old token, and the server switches only once a
// verified request uses the new one (Part 4, 5.5.2.1). This drives the real
// renewal path through handleOpenSecureChannelRequest.
func TestRenewalWaitsForSlowSwitchingClient(t *testing.T) {
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign} {
		t.Run(mode.String(), func(t *testing.T) {
			p := newRenewalPair(t, mode)

			p.read(t, nil)
			for round := 0; round < 2; round++ {
				old, err := p.cli.getActiveChannelInstance()
				require.NoError(t, err)
				require.NoError(t, p.cli.Renew(p.ctx))
				current, err := p.cli.getActiveChannelInstance()
				require.NoError(t, err)
				require.NotEqual(t, old.securityTokenID, current.securityTokenID)

				// The client has not switched yet.
				for i := 0; i < 3; i++ {
					p.read(t, old)
					require.Equal(t, old.securityTokenID, p.serverOutgoing(t), "round %d: server switched before the client", round)
				}
				// The client switches; the server follows.
				p.read(t, nil)
				require.Equal(t, current.securityTokenID, p.serverOutgoing(t), "round %d: server did not follow the client's switch", round)
			}
		})
	}
}

// A client may renew after its token's lifetime plus 25% has passed. A
// request it sent under the old token before it saw the renewal response
// must still verify, or the server drops the channel at the renewal.
func TestLateRenewalAcceptsRequestsUnderTheOldToken(t *testing.T) {
	p := newRenewalPair(t, ua.MessageSecurityModeSignAndEncrypt)
	p.read(t, nil)

	// Back-date the server's token to twice its lifetime ago.
	inst := p.serverInstance(t)
	inst.Lock()
	inst.createdAt = inst.createdAt.Add(-2 * time.Hour)
	inst.Unlock()

	old, err := p.cli.getActiveChannelInstance()
	require.NoError(t, err)
	require.NoError(t, p.cli.Renew(p.ctx))
	p.read(t, old)
	p.read(t, nil)
}
