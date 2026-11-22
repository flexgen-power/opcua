package opcua_test

import (
	"context"
	"fmt"
	"net"
	"runtime"
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
	endpoint := startServer(t)

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

	c, err := opcua.NewClient(endpoint,
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

// Dial must not connect the client when its context is canceled after
// OpenSecureChannel has completed.
func TestClientDialCanceledAfterOpen(t *testing.T) {
	c, err := opcua.NewClient(startServer(t),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.SecurityPolicy("None"),
		opcua.AuthAnonymous(),
		opcua.AutoReconnect(false),
		opcua.Dialer(&uacp.Dialer{
			// not uacp.DefaultClientACK, which other tests in this package change
			ClientACK: &uacp.Acknowledge{ReceiveBufSize: uacp.DefaultReceiveBufSize, SendBufSize: uacp.DefaultSendBufSize},
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = c.Dial(&cancelOnDialCheck{Context: ctx, cancel: cancel})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, c.SecureChannel())
}

// cancelOnDialCheck is canceled when Client.Dial asks for its error, which
// Dial does only after OpenSecureChannel has completed and before it connects
// the client.
type cancelOnDialCheck struct {
	context.Context
	cancel context.CancelFunc
}

func (c *cancelOnDialCheck) Err() error {
	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	if f, _ := runtime.CallersFrames(pc).Next(); f.Function == "github.com/gopcua/opcua.(*Client).Dial" {
		c.cancel()
	}
	return c.Context.Err()
}

// startServer starts a server without security and returns its endpoint.
func startServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	srv := server.New(
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { srv.Close() })
	return fmt.Sprintf("opc.tcp://127.0.0.1:%d", port)
}
