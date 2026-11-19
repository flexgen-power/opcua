package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

// A peer that has stopped reading fills the socket buffers, and the next write
// to it blocks. Telling it why its channel closed must not hold the channel,
// and the server's goroutine for it, open forever.
func TestCloseWithErrorDoesNotBlockOnAPeerThatStoppedReading(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c.(*net.TCPConn)
	}()
	peer, err := net.Dial("tcp", ln.Addr().String()) // never reads
	require.NoError(t, err)
	defer peer.Close()
	srvTCP := <-accepted
	require.NotNil(t, srvTCP)

	// Fill the kernel buffers in both directions until a write would block.
	chunk := make([]byte, 1<<16)
	for {
		srvTCP.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := srvTCP.Write(chunk); err != nil {
			break
		}
	}
	srvTCP.SetWriteDeadline(time.Time{})

	conn, err := uacp.NewConn(srvTCP, uacp.DefaultServerACK)
	require.NoError(t, err)

	done := make(chan struct{})
	start := time.Now()
	go func() {
		closeWithError(conn, ua.StatusBadSecurityChecksFailed, 300*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closeWithError blocked on a peer that stopped reading")
	}
	require.Less(t, time.Since(start), 3*time.Second)
	_, err = srvTCP.Write([]byte("x"))
	require.Error(t, err, "the connection must be closed afterwards")
}

func TestReceivePanicBecomesAChannelError(t *testing.T) {
	b := newChannelBroker(nil, time.Second, time.Second)
	msg := b.receive(context.Background(), func(context.Context) *uasc.MessageBody { panic("malformed chunk") })
	require.NotNil(t, msg)
	require.Error(t, msg.Err)
	require.Contains(t, msg.Err.Error(), "malformed chunk")

	// A receive that does not panic is passed through untouched.
	want := &uasc.MessageBody{RequestID: 7}
	require.Same(t, want, b.receive(context.Background(), func(context.Context) *uasc.MessageBody { return want }))
}
