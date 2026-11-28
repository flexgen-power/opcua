// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uatest_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uatest"
)

// startServer runs a server with one unsecured endpoint on a free port.
func startServer(t *testing.T) (endpoint string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	s := server.New(
		server.EndPoint("localhost", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return fmt.Sprintf("opc.tcp://localhost:%d", port)
}

const patience = 5 * time.Second

func TestHelloIsAcknowledged(t *testing.T) {
	endpoint := startServer(t)
	ack := uatest.Dial(t, endpoint).Hello(endpoint)
	if ack.ReceiveBufSize == 0 || ack.SendBufSize == 0 {
		t.Fatalf("the Acknowledge carries no buffer sizes: %+v", *ack)
	}
}

// A client says in its Hello how large a chunk it can take, and the server
// must not promise to send larger ones (Part 6, 7.1.3).
func TestTheAcknowledgeHonoursTheClientsReceiveBuffer(t *testing.T) {
	endpoint := startServer(t)
	p := uatest.Dial(t, endpoint)
	hello := uatest.DefaultHello(endpoint)
	hello.ReceiveBufSize = 9000
	p.WriteHello(hello)

	msgType, body, err := p.ReadFrame(patience)
	if err != nil || msgType != "ACKF" {
		t.Fatalf("got %q, %v; want an Acknowledge", msgType, err)
	}
	// The send buffer size is the third field: version, receive, send.
	if got := uint32(body[8]) | uint32(body[9])<<8 | uint32(body[10])<<16 | uint32(body[11])<<24; got != 9000 {
		t.Fatalf("the server will send chunks of up to %d bytes to a client that takes 9000", got)
	}
	p.ExpectOpenFor(200 * time.Millisecond)
}

// Whatever a peer sends in place of a well-formed frame in its turn, the
// server answers with an Error frame and closes the connection. Each case is
// one frame, sent before the Hello or after a completed handshake.
func TestAFrameOutOfTurnOrMalformedEndsTheConnection(t *testing.T) {
	endpoint := startServer(t)
	cases := []struct {
		name       string
		afterHello bool
		frame      []byte
	}{
		{"a message before the Hello", false, uatest.Frame("MSGF", make([]byte, 16))},
		{"an unknown message type before the Hello", false, uatest.Frame("XYZF", make([]byte, 8))},
		{"a Hello cut short", false, uatest.Frame("HELF", []byte{1, 2, 3})},
		{"a size larger than the receive buffer", false, uatest.FrameWithSize("HELF", 1<<30, make([]byte, 8))},
		{"a size smaller than the header", false, uatest.FrameWithSize("HELF", 4, nil)},
		{"a second Hello", true, uatest.Frame("HELF", make([]byte, 32))},
		{"an unknown message type after the Hello", true, uatest.Frame("XYZF", make([]byte, 32))},
		{"a message for a channel that was never opened", true, uatest.Frame("MSGF", make([]byte, 16))},
		{"an OpenSecureChannel cut short", true, uatest.Frame("OPNF", []byte{1, 2, 3})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := uatest.Dial(t, endpoint)
			if c.afterHello {
				p.Hello(endpoint)
			}
			p.Write(c.frame)
			if e := p.ExpectError(patience); ua.StatusCode(e.ErrorCode)&0x80000000 == 0 {
				t.Errorf("the Error frame carries %v, which is not a Bad status", ua.StatusCode(e.ErrorCode))
			}
			p.ExpectClosed(patience)
		})
	}

	// The server is still serving after all of that.
	uatest.Dial(t, endpoint).Hello(endpoint)
}

// A frame larger than the buffer agreed in the handshake cannot be read, so
// the connection ends, with or without an Error frame first.
func TestAFrameLargerThanTheAgreedBufferEndsTheConnection(t *testing.T) {
	endpoint := startServer(t)
	p := uatest.Dial(t, endpoint)
	p.Hello(endpoint)
	p.Write(uatest.FrameWithSize("MSGF", 1<<30, nil))
	p.ExpectClosed(patience)
}
