package uasc

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/uacp"
)

func TestResponseWriteDeadlineSelection(t *testing.T) {
	now := time.Unix(100, 0)
	ctxDeadline := now.Add(250 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), ctxDeadline)
	defer cancel()

	deadline, ok := responseWriteDeadline(ctx, time.Second, now)
	if !ok || !deadline.Equal(ctxDeadline) {
		t.Fatalf("deadline = %s, ok=%t; want %s", deadline, ok, ctxDeadline)
	}

	deadline, ok = responseWriteDeadline(context.Background(), 0, now)
	if ok || !deadline.IsZero() {
		t.Fatalf("disabled timeout returned deadline %s", deadline)
	}
}

func TestWriteResponseTimeoutClosesTransport(t *testing.T) {
	serverTCP, clientTCP := tcpPair(t)
	defer clientTCP.Close()
	if err := serverTCP.SetWriteBuffer(1024); err != nil {
		t.Fatalf("set write buffer: %v", err)
	}

	conn, err := uacp.NewConn(serverTCP, nil)
	if err != nil {
		t.Fatalf("new UACP connection: %v", err)
	}
	sc := &SecureChannel{
		c:   conn,
		cfg: &Config{ResponseWriteTimeout: 100 * time.Millisecond},
	}

	started := time.Now()
	_, timedOut, err := sc.writeResponse(context.Background(), make([]byte, 8<<20))
	if err == nil {
		t.Fatal("expected blocked response write to fail")
	}
	if !timedOut {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("write timeout took %s", elapsed)
	}
	if _, err := serverTCP.Write([]byte("closed")); err == nil {
		t.Fatal("transport remained writable after response timeout")
	}
}

func TestWriteResponseClearsDeadlineAfterSuccess(t *testing.T) {
	serverTCP, clientTCP := tcpPair(t)
	defer serverTCP.Close()
	defer clientTCP.Close()
	go func() { _, _ = io.Copy(io.Discard, clientTCP) }()

	conn, err := uacp.NewConn(serverTCP, nil)
	if err != nil {
		t.Fatalf("new UACP connection: %v", err)
	}
	sc := &SecureChannel{
		c:   conn,
		cfg: &Config{ResponseWriteTimeout: 50 * time.Millisecond},
	}

	if _, _, err := sc.writeResponse(context.Background(), []byte("first")); err != nil {
		t.Fatalf("first response write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := serverTCP.Write([]byte("second")); err != nil {
		t.Fatalf("stale write deadline remained after success: %v", err)
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server := <-accepted:
		return server, client
	case err := <-errs:
		client.Close()
		t.Fatalf("accept: %v", err)
		return nil, nil
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("accept timed out")
		return nil, nil
	}
}
