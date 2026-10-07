package server

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

// controllableNamespace wraps a NodeNameSpace so a test can intercept Attribute
// reads -- e.g. to hold one delivery mid-read while proving a second delivery
// for the same node cannot proceed concurrently with it.
//
// When current is set, Attribute samples it before calling onAttribute and
// returns that sample, modelling a read that completes and is then delayed
// before its result is handed on.
type controllableNamespace struct {
	*NodeNameSpace
	onAttribute func()
	current     *atomic.Int32
}

func (c *controllableNamespace) Attribute(id *ua.NodeID, a ua.AttributeID) *ua.DataValue {
	if c.current != nil {
		v := c.current.Load()
		if c.onAttribute != nil {
			c.onAttribute()
		}
		return DataValueFromValue(v)
	}
	if c.onAttribute != nil {
		c.onAttribute()
	}
	return c.NodeNameSpace.Attribute(id, a)
}

func monitorNode(srv *Server, sub *Subscription, id uint32, nodeID *ua.NodeID, clientHandle uint32) {
	item := &MonitoredItem{
		ID:  id,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: clientHandle},
		},
	}
	key := nodeID.String()
	srv.MonitoredItemService.Nodes[key] = append(srv.MonitoredItemService.Nodes[key], item)
}

// pendingValue returns the int32 value pending for clientHandle on sub, and
// whether one is pending at all.
func pendingValue(t *testing.T, sub *Subscription, clientHandle uint32) (int32, bool) {
	t.Helper()
	sub.pendingMu.Lock()
	defer sub.pendingMu.Unlock()
	n, ok := sub.pending[clientHandle]
	if !ok {
		return 0, false
	}
	v, isInt := n.Value.Value.Value().(int32)
	if !isInt {
		t.Fatalf("pending value for handle %d is %T, want int32", clientHandle, n.Value.Value.Value())
	}
	return v, true
}

// TestChangeNotificationsSerializesDeliveryPerNode proves the fix for the
// out-of-order-delivery hazard flagged in PR review: before this change, the
// attribute read and the channel send both happened under
// MonitoredItemService.Mu, so two ChangeNotification calls for the same node
// were implicitly serialized. Moving that work outside Mu (to fix the
// deadlock hazard) opened a window where two deliveries for the same node
// could interleave, letting an older value's send land after a newer value's
// send and become "latest" in a subscriber's publish queue.
//
// deliver's per-node lock closes that window by making delivery for a given
// node mutually exclusive again, independent of Mu. This test proves that
// exclusion directly: while one ChangeNotification call is blocked between
// reading an older value and handing it on, a second call for the same node
// cannot complete delivery, and once both finish the newer value is the one
// left pending for publish.
func TestChangeNotificationsSerializesDeliveryPerNode(t *testing.T) {
	srv := New()
	srv.initHandlers()
	inner := NewNodeNameSpace(srv, "dynamic")

	nodeID := ua.NewStringNodeID(inner.ID(), "race.value")
	child := NewVariableNode(nodeID, "value", int32(1))
	inner.AddNode(child)

	entered := make(chan struct{})
	release := make(chan struct{})
	var armed int32 = 1
	var current atomic.Int32
	current.Store(1)

	wrapped := &controllableNamespace{
		NodeNameSpace: inner,
		current:       &current,
		onAttribute: func() {
			// Only the first call blocks (CompareAndSwap, not sync.Once --
			// Once.Do blocks ALL concurrent callers until the winner's
			// function returns, which would make this pass regardless of
			// whether delivery is actually serialized). A second concurrent
			// call must sail through immediately if delivery for this node is
			// not serialized.
			if atomic.CompareAndSwapInt32(&armed, 1, 0) {
				close(entered)
				<-release
			}
		},
	}
	// Swap the server's registered namespace for the wrapper so delivery (which
	// looks the namespace up fresh via Server.Namespace) reads through it.
	srv.namespaces[inner.ID()] = wrapped

	sub := NewSubscription()
	monitorNode(srv, sub, 1, nodeID, 42)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		srv.ChangeNotification(nodeID)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first ChangeNotification did not reach the attribute read")
	}

	// The first delivery now holds value 1; the node has since moved on.
	current.Store(2)

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		srv.ChangeNotification(nodeID)
	}()

	// The second call must not be able to deliver while the first still holds
	// the per-node lock inside its (blocked) read -- that's the exclusion this
	// fix adds.
	select {
	case <-secondDone:
		t.Fatal("second ChangeNotification delivered while the first was still in flight for the same node")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	deadline := time.After(2 * time.Second)
	for firstDone != nil || secondDone != nil {
		select {
		case <-firstDone:
			firstDone = nil
		case <-secondDone:
			secondDone = nil
		case <-deadline:
			t.Fatal("first and second ChangeNotification did not both complete after release")
		}
	}

	if got := sub.PendingNotifications(); got != 1 {
		t.Fatalf("subscription has %d pending notifications, want 1 (coalesced per client handle)", got)
	}
	if v, ok := pendingValue(t, sub, 42); !ok || v != 2 {
		t.Fatalf("pending value for handle 42 = %d (present %v), want the newer value 2", v, ok)
	}
}

// TestChangeNotificationsNeverBlockOnUndrainedSubscription covers the ingest
// stall: delivery runs on the application's ingest goroutine, and a subscriber
// whose run() loop is not draining (here it was never started) must not slow
// that goroutine down. Far more changes are pushed than the old 100-deep
// channel could hold, and each monitored item must end up with exactly one
// pending notification carrying its latest value.
func TestChangeNotificationsNeverBlockOnUndrainedSubscription(t *testing.T) {
	srv := New()
	srv.initHandlers()
	inner := NewNodeNameSpace(srv, "dynamic")

	nodeA := ua.NewStringNodeID(inner.ID(), "a.value")
	nodeB := ua.NewStringNodeID(inner.ID(), "b.value")
	inner.AddNode(NewVariableNode(nodeA, "a", int32(0)))
	inner.AddNode(NewVariableNode(nodeB, "b", int32(0)))

	var current atomic.Int32
	srv.namespaces[inner.ID()] = &controllableNamespace{NodeNameSpace: inner, current: &current}

	sub := NewSubscription()
	monitorNode(srv, sub, 1, nodeA, 7)
	monitorNode(srv, sub, 2, nodeB, 8)

	const changes = 1000
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := int32(1); i <= changes; i++ {
			current.Store(i)
			srv.ChangeNotifications([]*ua.NodeID{nodeA, nodeB})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ChangeNotifications blocked on a subscription that is not draining")
	}

	if got := sub.PendingNotifications(); got != 2 {
		t.Fatalf("subscription has %d pending notifications, want 2 (one per monitored item)", got)
	}

	// What run() would publish next is whatever drainPending hands it.
	q := make(map[uint32]*ua.MonitoredItemNotification)
	sub.drainPending(q)
	for _, h := range []uint32{7, 8} {
		n, ok := q[h]
		if !ok {
			t.Fatalf("no notification queued for publish on handle %d", h)
		}
		if v := n.Value.Value.Value().(int32); v != changes {
			t.Fatalf("handle %d would publish %d, want latest value %d", h, v, changes)
		}
	}
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("%d notifications still pending after drain, want 0", got)
	}
}

// TestSubscriptionRunDrainsPendingOnWake checks that the publish loop picks up
// notifications from the pending set as they arrive, and that notifications
// after the subscription is deleted are dropped rather than retained.
func TestSubscriptionRunDrainsPendingOnWake(t *testing.T) {
	srv := New()
	srv.initHandlers()

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1
	// Long enough that the ticker never fires during the test, so run() sits
	// in its collection loop and never needs a session or publish request.
	sub.RevisedPublishingInterval = float64(time.Hour / time.Millisecond)
	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[sub.ID] = sub
	sub.running = true
	srv.SubscriptionService.Mu.Unlock()
	sub.Start()

	sub.Notify(&ua.MonitoredItemNotification{ClientHandle: 1, Value: DataValueFromValue(int32(1))})

	deadline := time.Now().Add(2 * time.Second)
	for sub.PendingNotifications() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("run() did not drain the pending notification after being woken")
		}
		time.Sleep(time.Millisecond)
	}

	srv.SubscriptionService.DeleteSubscription(sub.ID)
	sub.Notify(&ua.MonitoredItemNotification{ClientHandle: 2, Value: DataValueFromValue(int32(2))})
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("notification retained after subscription deleted: %d pending", got)
	}
}

// TestChangeNotificationsAfterShutdownIsNoOp covers delivery to a
// subscription whose run() goroutine has already exited and been torn down:
// the call must return promptly and must not leave anything pending behind.
func TestChangeNotificationsAfterShutdownIsNoOp(t *testing.T) {
	srv := New()
	srv.initHandlers()
	inner := NewNodeNameSpace(srv, "dynamic")

	nodeID := ua.NewStringNodeID(inner.ID(), "abandoned.value")
	child := NewVariableNode(nodeID, "value", int32(1))
	inner.AddNode(child)

	sub := NewSubscription()
	// Simulate a subscription whose run() goroutine has already exited and
	// been torn down, the way SubscriptionService.DeleteSubscription does it.
	sub.Mu.Lock()
	sub.running = false
	close(sub.shutdown)
	sub.Mu.Unlock()

	monitorNode(srv, sub, 1, nodeID, 7)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			srv.ChangeNotification(nodeID)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ChangeNotification hung delivering to a shut-down subscription")
	}

	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("shut-down subscription has %d pending notifications, want 0", got)
	}
}
