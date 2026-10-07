package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

type channelBroker struct {
	endpoints map[string]*ua.EndpointDescription

	wg sync.WaitGroup

	// mu protects concurrent modification of s, secureChannelID, and secureTokenID
	mu sync.RWMutex
	// s is a slice of all SecureChannels watched by the channelBroker
	s map[uint32]*uasc.SecureChannel

	// Next Secure Channel ID to issue to a client
	secureChannelID uint32

	// Next Token ID to issue to a client
	secureTokenID uint32

	// msgChan is the common channel that all messages from all channels
	// get funneled into for handling
	msgChan              chan *uasc.MessageBody
	logger               Logger
	responseWriteTimeout time.Duration

	// dispatchTimeout bounds each hand-off to msgChan; non-positive disables it.
	dispatchTimeout time.Duration
}

func newChannelBroker(logger Logger, responseWriteTimeout, dispatchTimeout time.Duration) *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		endpoints:            make(map[string]*ua.EndpointDescription),
		s:                    make(map[uint32]*uasc.SecureChannel),
		msgChan:              make(chan *uasc.MessageBody),
		secureChannelID:      uint32(rng.Int31()),
		secureTokenID:        uint32(rng.Int31()),
		logger:               logger,
		responseWriteTimeout: responseWriteTimeout,
		dispatchTimeout:      dispatchTimeout,
	}
}

// dispatch hands msg to the server's request dispatcher. It reports
// "context_done" or "dispatch_timeout" when the hand-off was abandoned, and ""
// once the dispatcher has taken the message.
func (c *channelBroker) dispatch(ctx context.Context, msg *uasc.MessageBody) string {
	var timeout <-chan time.Time
	if c.dispatchTimeout > 0 {
		t := time.NewTimer(c.dispatchTimeout)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case c.msgChan <- msg:
		return ""
	case <-ctx.Done():
		return "context_done"
	case <-timeout:
		return "dispatch_timeout"
	}
}

// RegisterConn connects a new UACP connection to the channel broker's list
// of connections and starts waiting for data on it.  Data is pushed onto the broker's
// Response channel
// Blocks until the context is done, the connection closes, or a critical error
func (c *channelBroker) RegisterConn(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) error {
	cfg := defaultChannelConfig()
	cfg.Certificate = localCert
	cfg.LocalKey = localKey
	cfg.Logger = c.logger
	cfg.ResponseWriteTimeout = c.responseWriteTimeout

	c.mu.Lock()
	c.secureChannelID++
	c.secureTokenID++
	secureChannelID := c.secureChannelID
	secureTokenID := c.secureTokenID
	sequenceNumber := uint32(mrand.Int31n(1023) + 1)
	c.mu.Unlock()

	errch := make(chan error, 1)
	sc, err := uasc.NewServerSecureChannel(
		"", // todo(fs): this is most likely wrong
		conn,
		cfg,
		errch,
		secureChannelID,
		sequenceNumber,
		secureTokenID,
	)
	if err != nil {
		if c.logger != nil {
			c.logger.Error("Error creating secure channel for new connection: %s", err)
		}
		return err
	}

	c.mu.Lock()
	c.s[secureChannelID] = sc
	channelCount := len(c.s)
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	// Logger callbacks are external code and must not run under the broker lock.
	emitDiagInfo(c.logger, diagPayload{
		Event:           "channel_registered",
		SecureChannelID: secureChannelID,
		ChannelCount:    &channelCount,
	})
	if c.logger != nil {
		c.logger.Info("Registered new channel (id %d) now at %d channels", secureChannelID, channelCount)
	}
	closeCause := "context_done"
	var closeErr string
outer:
	for {
		select {
		case <-ctx.Done():
			// todo(fs): return error?
			closeCause = "context_done"
			break outer

		default:
			msg := sc.Receive(ctx)
			if msg.Err == io.EOF {
				closeCause = "eof"
				break outer
			} else if msg.Err != nil {
				closeCause = "error"
				closeErr = msg.Err.Error()
				break outer
			}
			if cause := c.dispatch(ctx, msg); cause != "" {
				closeCause = cause
				if cause == "dispatch_timeout" {
					closeErr = fmt.Sprintf("request dispatcher did not accept a message within %s", c.dispatchTimeout)
					emitDiagWarn(c.logger, diagPayload{
						Event:           "channel_dispatch_timeout",
						SecureChannelID: secureChannelID,
						RemoteAddr:      remoteAddr(sc),
						ErrorText:       closeErr,
					})
					// Closing the TCP connection first makes the secure channel's
					// own close fail fast instead of writing to a peer that may
					// not be reading.
					conn.Close()
					sc.Close()
				}
				break outer
			}
		}
	}

	c.mu.Lock()
	delete(c.s, secureChannelID)
	remainingChannels := len(c.s)
	c.mu.Unlock()
	emitDiagInfo(c.logger, diagPayload{
		Event:           "channel_closed",
		SecureChannelID: secureChannelID,
		CloseCause:      closeCause,
		ErrorText:       closeErr,
		ChannelCount:    &remainingChannels,
	})
	if c.logger != nil {
		switch closeCause {
		case "context_done":
			c.logger.Warn("Context done, closing Secure Channel %d", secureChannelID)
		case "eof":
			c.logger.Warn("Secure Channel %d closed", secureChannelID)
		case "dispatch_timeout":
			c.logger.Warn("Secure Channel %d closed: %s", secureChannelID, closeErr)
		default:
			c.logger.Error("Secure Channel %d error: %s", secureChannelID, closeErr)
		}
	}
	return nil
}

// Close gracefully closes all secure channels
// todo(fs): use ctx
func (c *channelBroker) Close() error {
	var err error
	c.mu.Lock()
	for _, s := range c.s {
		s.Close()
	}
	c.mu.Unlock()

	// Wait for all goroutines to finish or timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second): // todo(fs): magic number
		if c.logger != nil {
			c.logger.Error("CloseAll: timed out waiting for channels to exit")
		}
	}

	return err
}

func (c *channelBroker) ReadMessage(ctx context.Context) *uasc.MessageBody {
	select {
	case <-ctx.Done():
		return nil
	case msg := <-c.msgChan:
		return msg
	}
}
