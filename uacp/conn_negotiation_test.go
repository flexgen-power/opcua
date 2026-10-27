// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The server must not send a chunk larger than the client said it can
// receive, and must remember the limits the client set on responses. Both are
// in the client's Hello, which the server used to read and ignore.
func TestServerHandshakeHonoursClientHello(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	l, err := Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer l.Close()
	endpoint := fmt.Sprintf("opc.tcp://%s", l.Addr().String())
	serverDefault := *DefaultServerACK

	handshake := func(t *testing.T, clientACK *Acknowledge) (srv, cli *Conn) {
		t.Helper()
		accepted := make(chan *Conn, 1)
		go func() {
			c, err := l.Accept(ctx)
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}()
		cli, err := (&Dialer{ClientACK: clientACK}).Dial(ctx, endpoint)
		require.NoError(t, err)
		t.Cleanup(func() { cli.Close() })
		srv = <-accepted
		require.NotNil(t, srv, "server did not accept")
		t.Cleanup(func() { srv.Close() })
		return srv, cli
	}

	t.Run("send buffer lowered to the client's receive buffer", func(t *testing.T) {
		srv, cli := handshake(t, &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 65535, MaxChunkCount: 3, MaxMessageSize: 40000})
		require.EqualValues(t, 8192, srv.SendBufSize())
		require.EqualValues(t, 8192, cli.SendBufSize(), "the ACK must tell the client the lowered size")
		require.EqualValues(t, 3, srv.PeerMaxChunkCount())
		require.EqualValues(t, 40000, srv.PeerMaxMessageSize())
	})

	t.Run("a larger client buffer does not raise the server's", func(t *testing.T) {
		srv, _ := handshake(t, &Acknowledge{ReceiveBufSize: 1 << 20, SendBufSize: 1 << 20})
		require.EqualValues(t, serverDefault.SendBufSize, srv.SendBufSize())
		require.EqualValues(t, 0, srv.PeerMaxChunkCount(), "no limit set means no limit")
	})

	t.Run("never below the protocol minimum", func(t *testing.T) {
		srv, _ := handshake(t, &Acknowledge{ReceiveBufSize: 100, SendBufSize: 65535})
		require.EqualValues(t, MinBufSize, srv.SendBufSize())
	})

	t.Run("a zero receive buffer sets no limit", func(t *testing.T) {
		// A real client cannot run with a zero buffer, so send the Hello by hand.
		accepted := make(chan *Conn, 1)
		go func() {
			c, err := l.Accept(ctx)
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}()
		raddr, err := net.ResolveTCPAddr("tcp", l.Addr().String())
		require.NoError(t, err)
		tcp, err := net.DialTCP("tcp", nil, raddr)
		require.NoError(t, err)
		raw, err := NewConn(tcp, DefaultClientACK)
		require.NoError(t, err)
		defer raw.Close()
		require.NoError(t, raw.Send("HELF", &Hello{ReceiveBufSize: 0, SendBufSize: 65535, EndpointURL: endpoint}))
		b, err := raw.Receive()
		require.NoError(t, err)
		ack := new(Acknowledge)
		_, err = ack.Decode(b[hdrlen:])
		require.NoError(t, err)
		require.EqualValues(t, serverDefault.SendBufSize, ack.SendBufSize)

		srv := <-accepted
		require.NotNil(t, srv)
		defer srv.Close()
		require.EqualValues(t, serverDefault.SendBufSize, srv.SendBufSize())
	})

	t.Run("one client's limits do not leak into the next", func(t *testing.T) {
		handshake(t, &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 8192})
		require.Equal(t, serverDefault, *DefaultServerACK, "the shared server ACK was modified")
		srv, _ := handshake(t, DefaultClientACK)
		require.EqualValues(t, serverDefault.SendBufSize, srv.SendBufSize())
	})
}
