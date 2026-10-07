package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

type recordingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *recordingLogger) record(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf(msg, args...))
}

func (l *recordingLogger) Debug(msg string, args ...any) { l.record(msg, args...) }
func (l *recordingLogger) Error(msg string, args ...any) { l.record(msg, args...) }
func (l *recordingLogger) Info(msg string, args ...any)  { l.record(msg, args...) }
func (l *recordingLogger) Warn(msg string, args ...any)  { l.record(msg, args...) }

func (l *recordingLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// brokerConn registers one loopback connection with cb and opens a client
// secure channel over it. Opening the channel makes the broker's reader
// produce a message for the dispatcher, which nothing in these tests consumes
// unless the test does so itself.
type brokerConn struct {
	done     chan struct{}
	clientSC *uasc.SecureChannel
	clientC  *uacp.Conn
	clientEr chan error
}

func registerLoopbackConn(t *testing.T, ctx context.Context, cb *channelBroker) *brokerConn {
	t.Helper()

	l, err := uacp.Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	type acceptResult struct {
		c   *uacp.Conn
		err error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept(ctx)
		accepted <- acceptResult{c, err}
	}()

	endpoint := "opc.tcp://" + l.Addr().String()
	clientC, err := uacp.Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { clientC.Close() })

	res := <-accepted
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() { res.c.Close() })

	bc := &brokerConn{done: make(chan struct{}), clientC: clientC, clientEr: make(chan error, 1)}
	go func() {
		defer close(bc.done)
		cb.RegisterConn(ctx, res.c, nil, nil)
	}()

	bc.clientSC, err = uasc.NewSecureChannel(endpoint, clientC, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    5 * time.Second,
	}, bc.clientEr)
	if err != nil {
		t.Fatalf("new client secure channel: %v", err)
	}
	if err := bc.clientSC.Open(ctx); err != nil {
		t.Fatalf("open client secure channel: %v", err)
	}
	t.Cleanup(func() { bc.clientSC.Close() })
	return bc
}

func channelCount(cb *channelBroker) int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return len(cb.s)
}

func TestRegisterConnClosesChannelWhenDispatcherStalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := &recordingLogger{}
	cb := newChannelBroker(logger, time.Second, 100*time.Millisecond)
	bc := registerLoopbackConn(t, ctx, cb)

	select {
	case <-bc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("RegisterConn still blocked handing a message to a dispatcher that never consumes")
	}

	if n := channelCount(cb); n != 0 {
		t.Fatalf("channel map has %d entries after dispatch timeout, want 0", n)
	}
	if !logger.contains(`"event":"channel_dispatch_timeout"`) {
		t.Fatal("no channel_dispatch_timeout diagnostic was logged")
	}
	if !logger.contains(`"close_cause":"dispatch_timeout"`) {
		t.Fatal("channel_closed diagnostic does not report close_cause dispatch_timeout")
	}

	// The server must actually drop the connection so the client notices.
	select {
	case err := <-bc.clientEr:
		if err == nil {
			t.Fatal("client reported a nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe the server closing the connection")
	}
}

func TestRegisterConnKeepsChannelWhileDispatcherCatchesUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
	}{
		{"bound disabled", 0},
		{"within bound", 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cb := newChannelBroker(nil, time.Second, tc.timeout)
			bc := registerLoopbackConn(t, ctx, cb)

			// Longer than the stalled-dispatcher test's bound, so a disabled
			// bound is distinguishable from a short one.
			select {
			case <-bc.done:
				t.Fatal("RegisterConn returned while the dispatcher was only slow")
			case <-time.After(300 * time.Millisecond):
			}
			if n := channelCount(cb); n != 1 {
				t.Fatalf("channel map has %d entries while dispatcher is slow, want 1", n)
			}

			readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
			defer readCancel()
			if msg := cb.ReadMessage(readCtx); msg == nil {
				t.Fatal("dispatcher did not receive the queued message")
			}

			select {
			case <-bc.done:
				t.Fatal("RegisterConn returned after the dispatcher accepted its message")
			case <-time.After(50 * time.Millisecond):
			}

			bc.clientC.Close()
			select {
			case <-bc.done:
			case <-time.After(5 * time.Second):
				t.Fatal("RegisterConn did not return after the client disconnected")
			}
			if n := channelCount(cb); n != 0 {
				t.Fatalf("channel map has %d entries after disconnect, want 0", n)
			}
		})
	}
}

func TestRegisterConnExitsOnContextDoneWhileDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := &recordingLogger{}
	cb := newChannelBroker(logger, time.Second, 0)
	bc := registerLoopbackConn(t, ctx, cb)

	cancel()
	select {
	case <-bc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("RegisterConn ignored context cancellation while handing off a message")
	}
	if n := channelCount(cb); n != 0 {
		t.Fatalf("channel map has %d entries after context cancellation, want 0", n)
	}
	if !logger.contains(`"close_cause":"context_done"`) {
		t.Fatal("channel_closed diagnostic does not report close_cause context_done")
	}
}
