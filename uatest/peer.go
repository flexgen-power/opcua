// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package uatest helps tests drive a server one frame at a time, as a peer
// that does not have to follow the protocol.
//
// The client in this module always sends what the specification asks for, so
// a test written with it cannot show what a server does with anything else: a
// frame that lies about its size, a message sent out of turn, a connection
// that says nothing. A Peer is a bare TCP connection with helpers to build
// and read OPC UA TCP frames (Part 6, 7.1), which is enough to write those
// tests in a few lines:
//
//	p := uatest.Dial(t, endpoint)
//	p.WriteFrame("MSGF", make([]byte, 16)) // a message before any Hello
//	p.ExpectError(time.Second)
//	p.ExpectClosed(time.Second)
//
// Every helper fails the test, through t.Fatalf, when the connection does not
// behave as the helper's name says.
package uatest

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
)

// HeaderLen is the size of the header that starts every frame: a three-letter
// message type, a chunk type and the frame's total size.
const HeaderLen = 8

// Frame returns a frame of the given type around body, with its true size in
// the header. msgType is the message type and the chunk type together, as the
// specification writes them: "HELF", "OPNF", "MSGC".
func Frame(msgType string, body []byte) []byte {
	return FrameWithSize(msgType, uint32(HeaderLen+len(body)), body)
}

// FrameWithSize is Frame with the header's size field set to size, whatever
// the length of body.
func FrameWithSize(msgType string, size uint32, body []byte) []byte {
	if len(msgType) != 4 {
		panic("uatest: a frame type is four characters, such as \"HELF\"")
	}
	b := make([]byte, HeaderLen, HeaderLen+len(body))
	copy(b, msgType)
	binary.LittleEndian.PutUint32(b[4:], size)
	return append(b, body...)
}

// Peer is one TCP connection to a server.
type Peer struct {
	t    testing.TB
	conn net.Conn
}

// Dial connects to the host and port of an opc.tcp endpoint URL and sends
// nothing. The connection is closed when the test ends.
func Dial(t testing.TB, endpoint string) *Peer {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		t.Fatalf("uatest: %q is not an endpoint URL: %v", endpoint, err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("uatest: dial %s: %v", u.Host, err)
	}
	p := &Peer{t: t, conn: conn}
	t.Cleanup(p.Close)
	return p
}

// Close closes the connection. It may be called more than once.
func (p *Peer) Close() { _ = p.conn.Close() }

// Write sends b as it is.
func (p *Peer) Write(b []byte) {
	p.t.Helper()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.conn.Write(b); err != nil {
		p.t.Fatalf("uatest: write %d bytes: %v", len(b), err)
	}
}

// WriteFrame sends Frame(msgType, body).
func (p *Peer) WriteFrame(msgType string, body []byte) {
	p.t.Helper()
	p.Write(Frame(msgType, body))
}

// DefaultHello is the Hello that Hello sends: the limits this module's own
// client asks for.
func DefaultHello(endpoint string) *uacp.Hello {
	return &uacp.Hello{
		Version:        0,
		ReceiveBufSize: uacp.DefaultReceiveBufSize,
		SendBufSize:    uacp.DefaultSendBufSize,
		MaxMessageSize: uacp.DefaultMaxMessageSize,
		MaxChunkCount:  uacp.DefaultMaxChunkCount,
		EndpointURL:    endpoint,
	}
}

// WriteHello sends h as a Hello frame.
func (p *Peer) WriteHello(h *uacp.Hello) {
	p.t.Helper()
	body, err := ua.Encode(h)
	if err != nil {
		p.t.Fatalf("uatest: encode Hello: %v", err)
	}
	p.WriteFrame("HELF", body)
}

// Hello completes the handshake as a well-behaved client would and returns
// the server's Acknowledge.
func (p *Peer) Hello(endpoint string) *uacp.Acknowledge {
	p.t.Helper()
	p.WriteHello(DefaultHello(endpoint))
	msgType, body, err := p.ReadFrame(5 * time.Second)
	if err != nil {
		p.t.Fatalf("uatest: no answer to Hello: %v", err)
	}
	if msgType != "ACKF" {
		p.t.Fatalf("uatest: Hello was answered with %s, want ACKF", msgType)
	}
	ack := new(uacp.Acknowledge)
	if _, err := ack.Decode(body); err != nil {
		p.t.Fatalf("uatest: decode Acknowledge: %v", err)
	}
	return ack
}

// ReadFrame reads one frame, waiting up to within for all of it. It returns
// io.EOF when the server closed the connection before a frame began, and an
// error for which IsTimeout is true when nothing arrived in time.
func (p *Peer) ReadFrame(within time.Duration) (msgType string, body []byte, err error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(within))
	hdr := make([]byte, HeaderLen)
	if _, err := io.ReadFull(p.conn, hdr); err != nil {
		return "", nil, closedAsEOF(err)
	}
	size := binary.LittleEndian.Uint32(hdr[4:])
	if size < HeaderLen || size > 64<<20 {
		return string(hdr[:4]), nil, errors.New("uatest: the server sent a frame with an impossible size")
	}
	body = make([]byte, size-HeaderLen)
	if _, err := io.ReadFull(p.conn, body); err != nil {
		return string(hdr[:4]), nil, closedAsEOF(err)
	}
	return string(hdr[:4]), body, nil
}

// IsTimeout reports whether err, from ReadFrame, means that nothing arrived
// in time and the connection is still open.
func IsTimeout(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

// closedAsEOF turns the several ways a read reports a connection the other
// side closed, cleanly or with a reset, into io.EOF.
func closedAsEOF(err error) error {
	if err == nil || IsTimeout(err) {
		return err
	}
	return io.EOF
}

// ExpectError reads the next frame, which must be an Error frame, and returns
// it.
func (p *Peer) ExpectError(within time.Duration) *uacp.Error {
	p.t.Helper()
	msgType, body, err := p.ReadFrame(within)
	if err != nil {
		p.t.Fatalf("uatest: want an Error frame, got %v", describe(err))
	}
	if msgType != "ERRF" {
		p.t.Fatalf("uatest: want an Error frame, got %s", msgType)
	}
	e := new(uacp.Error)
	if _, err := e.Decode(body); err != nil {
		p.t.Fatalf("uatest: decode Error frame: %v", err)
	}
	return e
}

// ExpectClosed waits for the server to close the connection, reading and
// discarding anything it sends first.
func (p *Peer) ExpectClosed(within time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(within)
	for {
		_, _, err := p.ReadFrame(time.Until(deadline))
		switch {
		case err == nil:
			continue
		case IsTimeout(err):
			p.t.Fatalf("uatest: the server kept the connection open for %s", within)
		}
		return
	}
}

// ExpectOpenFor checks that the server neither closes the connection nor
// sends anything for d.
func (p *Peer) ExpectOpenFor(d time.Duration) {
	p.t.Helper()
	msgType, _, err := p.ReadFrame(d)
	switch {
	case err == nil:
		p.t.Fatalf("uatest: the server sent %s; want silence for %s", msgType, d)
	case !IsTimeout(err):
		p.t.Fatalf("uatest: the server closed the connection within %s", d)
	}
}

func describe(err error) string {
	switch {
	case IsTimeout(err):
		return "nothing in time"
	case errors.Is(err, io.EOF):
		return "a closed connection"
	}
	return err.Error()
}
