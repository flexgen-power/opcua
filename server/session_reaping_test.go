package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestUnactivatedSessionsReapedAfterChannelClose(t *testing.T) {
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 5 {
		c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
		require.NoError(t, err)
		require.NoError(t, c.Dial(ctx))
		for range 16 {
			_, err := c.CreateSession(ctx, opcua.DefaultSessionConfig())
			require.NoError(t, err)
		}
		_, err = c.CreateSession(ctx, opcua.DefaultSessionConfig())
		requireStatus(t, err, ua.StatusBadTooManySessions)
		require.LessOrEqual(t, ss.srv.SessionCount(), 16)
		require.NoError(t, c.Close(ctx))
		require.Eventually(t, func() bool { return ss.srv.SessionCount() == 0 }, 2*time.Second, 10*time.Millisecond)
	}
}

func TestIdleSessionReapsSubscriptionsAndMonitoredItems(t *testing.T) {
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	defer c.Close(ctx)
	cfg := opcua.DefaultSessionConfig()
	cfg.SessionTimeout = 500 * time.Millisecond
	sess, err := c.CreateSession(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, c.ActivateSession(ctx, sess))
	token := ss.srv.ActivatedSessionTokens()[0]
	r, err := sendFor(ctx, c.SecureChannel(), &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 100, RequestedLifetimeCount: 1000, RequestedMaxKeepAliveCount: 10, PublishingEnabled: true,
	}, token, time.Second)
	require.NoError(t, err)
	subID := r.(*ua.CreateSubscriptionResponse).SubscriptionID
	_, err = sendFor(ctx, c.SecureChannel(), &ua.CreateMonitoredItemsRequest{
		SubscriptionID: subID, TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{opcua.NewMonitoredItemCreateRequestWithDefaults(ss.node.ID(), ua.AttributeIDValue, 1)},
	}, token, time.Second)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return ss.srv.SessionCount() == 0 }, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		ss.srv.SubscriptionService.Mu.Lock()
		subs := len(ss.srv.SubscriptionService.Subs)
		ss.srv.SubscriptionService.Mu.Unlock()
		ss.srv.MonitoredItemService.Mu.Lock()
		items := len(ss.srv.MonitoredItemService.Items)
		ss.srv.MonitoredItemService.Mu.Unlock()
		return subs == 0 && items == 0
	}, time.Second, 10*time.Millisecond)
	_, err = c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}})
	requireStatus(t, err, ua.StatusBadSessionIDInvalid)
}

// timedSession activates a session with the given timeout, waiting
// beforeActivate between CreateSession and ActivateSession.
func timedSession(t *testing.T, ctx context.Context, timeout, beforeActivate time.Duration) (*secureServer, *opcua.Client) {
	t.Helper()
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	t.Cleanup(func() { c.Close(context.Background()) })
	cfg := opcua.DefaultSessionConfig()
	cfg.SessionTimeout = timeout
	sess, err := c.CreateSession(ctx, cfg)
	require.NoError(t, err)
	time.Sleep(beforeActivate)
	require.NoError(t, c.ActivateSession(ctx, sess))
	return ss, c
}

// Every request a session accepts restarts its idle clock, so a session in use
// outlives its timeout.
func TestRequestsKeepSessionAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ss, c := timedSession(t, ctx, time.Second, 0)
	for deadline := time.Now().Add(2500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}})
		require.NoError(t, err)
	}
	require.Equal(t, 1, ss.srv.SessionCount())
}

// A client that only subscribes sends nothing but Publish requests, and those
// alone keep its session and subscription alive.
func TestPublishKeepsSessionAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AuthAnonymous(), opcua.SessionTimeout(time.Second), opcua.AutoReconnect(false))
	require.NoError(t, err)
	// Connect, not Dial: the client runs its publish loop only after Connect.
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { c.Close(context.Background()) })
	notifs := make(chan *opcua.PublishNotificationData, 64)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-notifs:
			}
		}
	}()
	_, err = c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 100 * time.Millisecond, MaxKeepAliveCount: 2}, notifs)
	require.NoError(t, err)
	time.Sleep(2500 * time.Millisecond)
	require.Equal(t, 1, ss.srv.SessionCount())
	ss.srv.SubscriptionService.Mu.Lock()
	subs := len(ss.srv.SubscriptionService.Subs)
	ss.srv.SubscriptionService.Mu.Unlock()
	require.Equal(t, 1, subs)
}

// ActivateSession restarts the idle clock, so the timeout runs from the last
// activation, not from CreateSession.
func TestActivateSessionRestartsIdleClock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ss, c := timedSession(t, ctx, time.Second, 600*time.Millisecond)
	time.Sleep(600 * time.Millisecond)
	_, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
}

// Publish requests the server holds for a subscription are outstanding requests
// on the session. When the session times out they must be answered with
// Bad_SessionClosed (Part 4, 5.6.2), not left for the client to time out.
func TestReapedSessionAbortsHeldPublishRequests(t *testing.T) {
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	defer c.Close(ctx)
	cfg := opcua.DefaultSessionConfig()
	cfg.SessionTimeout = 500 * time.Millisecond
	sess, err := c.CreateSession(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, c.ActivateSession(ctx, sess))
	token := ss.srv.ActivatedSessionTokens()[0]
	// The first keepalive is due (10+1) x 500 ms after this, well after the
	// session times out, so the subscription answers none of the requests.
	_, err = sendFor(ctx, c.SecureChannel(), &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 500, RequestedLifetimeCount: 1000, RequestedMaxKeepAliveCount: 10, PublishingEnabled: true,
	}, token, time.Second)
	require.NoError(t, err)

	const held = 3
	start := time.Now()
	errs := make(chan error, held)
	for range held {
		go func() {
			_, err := sendFor(ctx, c.SecureChannel(), &ua.PublishRequest{
				SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
			}, token, 3*time.Second)
			errs <- err
		}()
	}
	for range held {
		requireStatus(t, <-errs, ua.StatusBadSessionClosed)
	}
	require.Less(t, time.Since(start), 2*time.Second, "held Publish requests were answered only by the client's timeout")
	require.Equal(t, 0, ss.srv.SessionCount())
}

// A request counts toward its session from when the server received it, not
// from when the single request dispatcher got to it. A client that sent a
// request within its session timeout keeps its session while the dispatcher
// spends longer than that timeout on another client's request.
func TestDispatcherStallKeepsSessionWithQueuedRequest(t *testing.T) {
	ss := startSecureServer(t, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	activated := func(timeout time.Duration) *opcua.Client {
		c, err := opcua.NewClient(ss.addr, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
		require.NoError(t, err)
		require.NoError(t, c.Dial(ctx))
		t.Cleanup(func() { c.Close(context.Background()) })
		cfg := opcua.DefaultSessionConfig()
		cfg.SessionTimeout = timeout
		sess, err := c.CreateSession(ctx, cfg)
		require.NoError(t, err)
		require.NoError(t, c.ActivateSession(ctx, sess))
		return c
	}
	read := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ss.node.ID(), AttributeID: ua.AttributeIDValue}}}
	const timeout = time.Second
	busy := activated(time.Minute)
	c := activated(timeout)
	_, err := c.Read(ctx, read)
	require.NoError(t, err)
	stallStart := time.Now()

	// CreateSubscription waits for this lock, and the dispatcher waits with it.
	ss.srv.SubscriptionService.Mu.Lock()
	stalled := make(chan error, 1)
	go func() {
		stalled <- busy.Send(ctx, &ua.CreateSubscriptionRequest{
			RequestedPublishingInterval: 100, RequestedLifetimeCount: 1000, RequestedMaxKeepAliveCount: 10,
		}, func(ua.Response) error { return nil })
	}()
	time.Sleep(100 * time.Millisecond)
	queued := make(chan error, 1)
	go func() {
		_, err := c.Read(ctx, read)
		queued <- err
	}()
	time.Sleep(2*timeout - time.Since(stallStart))
	ss.srv.SubscriptionService.Mu.Unlock()

	require.NoError(t, <-stalled)
	require.NoError(t, <-queued, "a request received within the session timeout found its session closed")
}
