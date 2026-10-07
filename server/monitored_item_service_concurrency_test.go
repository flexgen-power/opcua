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
type controllableNamespace struct {
	*NodeNameSpace
	onAttribute func()
}

func (c *controllableNamespace) Attribute(id *ua.NodeID, a ua.AttributeID) *ua.DataValue {
	if c.onAttribute != nil {
		c.onAttribute()
	}
	return c.NodeNameSpace.Attribute(id, a)
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
// exclusion directly: while one ChangeNotification call is blocked mid-read
// for a node, a second call for the same node cannot complete delivery.
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

	wrapped := &controllableNamespace{
		NodeNameSpace: inner,
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
	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 42},
		},
	}
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}

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

	if got := len(sub.NotifyChannel); got != 2 {
		t.Fatalf("NotifyChannel has %d pending notifications, want 2", got)
	}
}

// TestChangeNotificationsDoesNotHangOnShutdownSubscription proves the fix for
// the hang hazard flagged in PR review: once delivery no longer happens under
// Mu, an unconditional send to a subscription whose run() goroutine already
// exited (its NotifyChannel permanently undrained) would block the calling
// goroutine forever once the buffer filled. deliver's select against the
// subscription's shutdown channel bounds that wait instead.
func TestChangeNotificationsDoesNotHangOnShutdownSubscription(t *testing.T) {
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

	// Fill the NotifyChannel so an unconditional send would block forever.
	for i := 0; i < cap(sub.NotifyChannel); i++ {
		sub.NotifyChannel <- &ua.MonitoredItemNotification{}
	}

	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 7},
		},
	}
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ChangeNotification(nodeID)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ChangeNotification hung delivering to a shut-down subscription with a full NotifyChannel")
	}
}
