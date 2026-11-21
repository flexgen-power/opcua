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
