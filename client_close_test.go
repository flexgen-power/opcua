package opcua_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/stretchr/testify/require"
)

// Close must not wait for a Connect whose dial is still in progress, and that
// dial must not leave the client connected after Close has returned.
func TestClientCloseDuringConnect(t *testing.T) {
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	srv := server.New(
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { srv.Close() })

	// The dial stops before it connects and waits for release, which comes
	// once Close has returned.
	dialing := make(chan struct{})
	release := make(chan struct{})
	notifyDialing := sync.OnceFunc(func() { close(dialing) })
	releaseDial := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseDial)
	dialer := &uacp.Dialer{
		Dialer: &net.Dialer{
			ControlContext: func(context.Context, string, string, syscall.RawConn) error {
				notifyDialing()
				<-release
				return nil
			},
		},
		// not uacp.DefaultClientACK, which other tests in this package change
		ClientACK: &uacp.Acknowledge{ReceiveBufSize: uacp.DefaultReceiveBufSize, SendBufSize: uacp.DefaultSendBufSize},
	}

	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://127.0.0.1:%d", port),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.SecurityPolicy("None"),
		opcua.AuthAnonymous(),
		opcua.AutoReconnect(false),
		opcua.Dialer(dialer),
	)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close(ctx) })

	connected := make(chan error, 1)
	go func() { connected <- c.Connect(ctx) }()
	<-dialing

	closed := make(chan error, 1)
	go func() { closed <- c.Close(ctx) }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		releaseDial()
		require.Fail(t, "Close waits for a dial in progress")
	}

	// The dial now reaches the server and opens a secure channel, which it
	// must close instead of connecting the client.
	releaseDial()
	select {
	case err := <-connected:
		require.ErrorContains(t, err, "client closed while dialing")
	case <-time.After(10 * time.Second):
		require.Fail(t, "Connect did not return")
	}
	require.Nil(t, c.SecureChannel())
	require.Equal(t, opcua.Closed, c.State())
}
