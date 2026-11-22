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

// Namespaces are written by the application on its own goroutines, without any
// lock the server holds, and a sampling timer fires while those writes go on. A
// deferred sample must therefore deliver the value read when the change was
// reported rather than read the node again on the timer's goroutine. Both tests
// below write a monitored node faster than its sampling interval; run them with
// -race.
func TestDeferredSamplesDoNotReadNodeNameSpaceOnTimer(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := NewNodeNameSpace(srv, "sampling")
	node := ns.AddNode(NewVariableNode(ua.NewStringNodeID(ns.ID(), "value"), "value", int32(0)))
	sub := NewSubscription()
	monitorNode(srv, sub, 1, node.ID(), 42)
	item := srv.MonitoredItemService.Nodes[node.ID().String()][0]
	item.sampleInterval = time.Millisecond
	t.Cleanup(item.stopSampling)

	var last int32
	for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
		last++
		if got := ns.SetAttribute(node.ID(), ua.AttributeIDValue, DataValueFromValue(last)); got != ua.StatusOK {
			t.Fatalf("SetAttribute = %v", got)
		}
	}
	waitForPendingValue(t, sub, 42, last)
}

func TestDeferredSamplesDoNotReadMapNamespaceOnTimer(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := NewMapNamespace(srv, "sampling")
	ns.SetValue("value", int32(0))
	node := ua.NewStringNodeID(ns.ID(), "value")
	sub := NewSubscription()
	monitorNode(srv, sub, 1, node, 42)
	item := srv.MonitoredItemService.Nodes[node.String()][0]
	item.sampleInterval = time.Millisecond
	t.Cleanup(item.stopSampling)

	var last int32
	for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
		last++
		ns.SetValue("value", last)
	}
	waitForPendingValue(t, sub, 42, last)
}

// waitForPendingValue waits for the final update of a burst to arrive.
func waitForPendingValue(t *testing.T, sub *Subscription, clientHandle uint32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, ok := pendingValue(t, sub, clientHandle)
		if ok && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("final update = %d (present %v), want %d", got, ok, want)
		}
		time.Sleep(time.Millisecond)
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

// A server-wide MinimumSamplingInterval applies to every monitored item,
// including one created before its node exists, and a node's own
// MinimumSamplingInterval attribute can only raise it.
func TestCreateMonitoredItemsHonorsServerMinimumSamplingInterval(t *testing.T) {
	srv := New(MinimumSamplingInterval(1000))
	srv.initHandlers()
	sess := srv.sb.NewSession()
	subID := createTestSubscription(t, srv, sess)
	ns := NewNodeNameSpace(srv, "sampling")
	withFloor := func(name string, floor float64) *ua.NodeID {
		node := NewVariableNode(ua.NewStringNodeID(ns.ID(), name), name, int32(0))
		if err := node.SetAttribute(ua.AttributeIDMinimumSamplingInterval, DataValueFromValue(floor)); err != nil {
			t.Fatalf("SetAttribute: %v", err)
		}
		return ns.AddNode(node).ID()
	}
	nodes := []*ua.NodeID{
		ua.NewStringNodeID(ns.ID(), "not-yet-created"),
		withFloor("lower", 250),
		withFloor("higher", 2000),
	}
	var items []*ua.MonitoredItemCreateRequest
	for i, node := range nodes {
		items = append(items, &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue},
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: uint32(i + 1), SamplingInterval: 100},
		})
	}
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader:  &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		SubscriptionID: subID,
		ItemsToCreate:  items,
	}, 0)
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	results := resp.(*ua.CreateMonitoredItemsResponse).Results
	for i, want := range []float64{1000, 1000, 2000} {
		r := results[i]
		if r.StatusCode != ua.StatusOK || r.RevisedSamplingInterval != want {
			t.Fatalf("%s: result %+v, want StatusOK with revised interval %v", nodes[i], r, want)
		}
		srv.MonitoredItemService.Mu.Lock()
		item := srv.MonitoredItemService.Items[r.MonitoredItemID]
		srv.MonitoredItemService.Mu.Unlock()
		item.sampleMu.Lock()
		got := item.sampleInterval
		item.sampleMu.Unlock()
		if got != time.Duration(want)*time.Millisecond {
			t.Fatalf("%s: item samples every %v, want %v ms", nodes[i], got, want)
		}
	}
}
