package server

import (
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

func TestReviseSamplingInterval(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		requested, publishing, minimum, want float64
	}{
		{"fast", 100, 100, 1000, 1000},
		{"continuous", 0, 100, 1000, 1000},
		{"inherit", -1, 2000, 1000, 2000},
		{"slow", 2000, 100, 1000, 2000},
		{"unbounded", 0, 100, 0, 0},
		{"nan", math.NaN(), 100, 1000, 1000},
		{"infinity", math.Inf(1), 100, 1000, maxPublishingInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reviseSamplingInterval(tc.requested, tc.publishing, tc.minimum); got != tc.want {
				t.Fatalf("interval %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSamplingCoalescesFinalUpdateAndStopsOnDeletion(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := NewNodeNameSpace(srv, "sampling")
	var value atomic.Int32
	node := ns.AddNode(NewVariableNode(ua.NewStringNodeID(ns.ID(), "value"), "value", ValueFunc(func() *ua.DataValue {
		return DataValueFromValue(value.Load())
	})))
	sub := NewSubscription()
	monitorNode(srv, sub, 1, node.ID(), 42)
	item := srv.MonitoredItemService.Nodes[node.ID().String()][0]
	item.sampleInterval = 100 * time.Millisecond
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Subs[sub.ID] = []*MonitoredItem{item}
	t.Cleanup(func() { srv.MonitoredItemService.DeleteMonitoredItem(item.ID) })

	srv.ChangeNotification(node.ID())
	sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	start := time.Now()
	for i := int32(1); i <= 100; i++ {
		value.Store(i)
		srv.ChangeNotification(node.ID())
	}
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("%d notifications before the sampling interval", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for sub.PendingNotifications() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got, ok := pendingValue(t, sub, 42); !ok || got != 100 {
		t.Fatalf("final update = %d (present %v), want 100", got, ok)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("deferred sample arrived too early")
	}
	sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	time.Sleep(120 * time.Millisecond)
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("%d extra notifications without another change", got)
	}
	// Queue another deferred sample, then delete it before its deadline.
	srv.ChangeNotification(node.ID())
	sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	value.Store(101)
	srv.ChangeNotification(node.ID())
	srv.MonitoredItemService.DeleteMonitoredItem(item.ID)
	time.Sleep(120 * time.Millisecond)
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("deleted item delivered %d pending notifications", got)
	}
}

func TestSamplingRetainsFinalUpdateAcrossConsecutiveWindows(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := NewNodeNameSpace(srv, "sampling")
	var value atomic.Int32
	node := ns.AddNode(NewVariableNode(ua.NewStringNodeID(ns.ID(), "value"), "value", ValueFunc(func() *ua.DataValue {
		return DataValueFromValue(value.Load())
	})))
	sub := NewSubscription()
	monitorNode(srv, sub, 1, node.ID(), 42)
	item := srv.MonitoredItemService.Nodes[node.ID().String()][0]
	item.sampleInterval = 100 * time.Millisecond
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Subs[sub.ID] = []*MonitoredItem{item}
	t.Cleanup(func() { srv.MonitoredItemService.DeleteMonitoredItem(item.ID) })

	srv.ChangeNotification(node.ID())
	sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	// Each burst lands inside the window that the previous timer-delivered
	// sample opened, so every final value must arrive through a new timer.
	for _, final := range []int32{10, 20, 30} {
		for v := final - 9; v <= final; v++ {
			value.Store(v)
			srv.ChangeNotification(node.ID())
		}
		if got := sub.PendingNotifications(); got != 0 {
			t.Fatalf("window ending %d: %d notifications before the sampling interval", final, got)
		}
		deadline := time.Now().Add(2 * time.Second)
		for sub.PendingNotifications() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got, ok := pendingValue(t, sub, 42); !ok || got != final {
			t.Fatalf("window ending %d delivered %d (present %v)", final, got, ok)
		}
		sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	}
}

// CreateMonitoredItems revises each item's sampling interval against its node's
// MinimumSamplingInterval attribute, samples at that revised interval, and
// rejects an item that does not name a node.
func TestCreateMonitoredItemsHonorsNodeMinimumSamplingInterval(t *testing.T) {
	srv := New()
	srv.initHandlers()
	sess := srv.sb.NewSession()
	subID := createTestSubscription(t, srv, sess)
	ns := NewNodeNameSpace(srv, "sampling")
	node := NewVariableNode(ua.NewStringNodeID(ns.ID(), "floor"), "floor", int32(0))
	if err := node.SetAttribute(ua.AttributeIDMinimumSamplingInterval, DataValueFromValue(1000.0)); err != nil {
		t.Fatalf("SetAttribute: %v", err)
	}
	ns.AddNode(node)

	monitor := func(handle uint32, interval float64) *ua.MonitoredItemCreateRequest {
		return &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: node.ID(), AttributeID: ua.AttributeIDValue},
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: handle, SamplingInterval: interval},
		}
	}
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader:  &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		SubscriptionID: subID,
		ItemsToCreate:  []*ua.MonitoredItemCreateRequest{monitor(1, 100), monitor(2, 2000), {}},
	}, 0)
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	results := resp.(*ua.CreateMonitoredItemsResponse).Results
	if len(results) != 3 {
		t.Fatalf("%d results, want 3", len(results))
	}
	for i, want := range []float64{1000, 2000} {
		r := results[i]
		if r.StatusCode != ua.StatusOK || r.RevisedSamplingInterval != want {
			t.Fatalf("result %d = %+v, want StatusOK with revised interval %v", i, r, want)
		}
		srv.MonitoredItemService.Mu.Lock()
		item := srv.MonitoredItemService.Items[r.MonitoredItemID]
		srv.MonitoredItemService.Mu.Unlock()
		if item == nil {
			t.Fatalf("item %d (id %d) was not registered", i, r.MonitoredItemID)
		}
		item.sampleMu.Lock()
		got := item.sampleInterval
		item.sampleMu.Unlock()
		if got != time.Duration(want)*time.Millisecond {
			t.Fatalf("item %d samples every %v, want %v ms", i, got, want)
		}
	}
	if got := results[2].StatusCode; got != ua.StatusBadInvalidArgument {
		t.Fatalf("empty item result %v, want BadInvalidArgument", got)
	}
}
