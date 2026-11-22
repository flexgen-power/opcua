package server

import (
	"math"
	"sync"
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
// reported rather than read the node again on the timer's goroutine.
//
// appLockedNameSpace stands for an application that writes its nodes and
// reports their changes while holding mu, as MapNamespace.SetValue does with
// its Mu. Attribute counts the calls made while mu is free: the reporting
// goroutine holds it, so those can only come from another goroutine.
type appLockedNameSpace struct {
	*NodeNameSpace
	mu            sync.Mutex
	unlockedReads atomic.Int32
}

func (ns *appLockedNameSpace) Attribute(id *ua.NodeID, attr ua.AttributeID) *ua.DataValue {
	if ns.mu.TryLock() {
		ns.mu.Unlock()
		ns.unlockedReads.Add(1)
	}
	return ns.NodeNameSpace.Attribute(id, attr)
}

// The final value of a burst arrives through the sampling timer without the
// namespace being read outside the reporting goroutine. This does not depend
// on the race detector, since Node's own lock makes such a read race-free.
func TestDeferredSamplesDoNotReadNameSpaceOnTimer(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := &appLockedNameSpace{NodeNameSpace: NewNameSpace("sampling")}
	srv.AddNamespace(ns)
	node := ns.AddNode(NewVariableNode(ua.NewStringNodeID(ns.ID(), "value"), "value", int32(0)))
	sub := NewSubscription()
	monitorNode(srv, sub, 1, node.ID(), 42)
	item := srv.MonitoredItemService.Nodes[node.ID().String()][0]
	item.sampleInterval = 100 * time.Millisecond
	t.Cleanup(item.stopSampling)

	write := func(v int32) {
		ns.mu.Lock()
		defer ns.mu.Unlock()
		if err := node.SetAttribute(ua.AttributeIDValue, DataValueFromValue(v)); err != nil {
			t.Fatalf("SetAttribute: %v", err)
		}
		srv.ChangeNotification(node.ID())
	}
	// The first change opens a sampling window and the rest land inside it.
	write(0)
	sub.drainPending(make(map[uint32]*ua.MonitoredItemNotification))
	for v := int32(1); v <= 10; v++ {
		write(v)
	}
	if got := sub.PendingNotifications(); got != 0 {
		t.Fatalf("%d notifications before the sampling interval", got)
	}
	waitForPendingValue(t, sub, 42, 10)
	if got := ns.unlockedReads.Load(); got != 0 {
		t.Fatalf("the namespace was read %d times outside the reporting goroutine", got)
	}
}

// MapNamespace reads its Data map without a lock, so a read on the timer's
// goroutine races SetValue. Run this with -race.
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

// A negative, NaN or infinite server MinimumSamplingInterval counts as zero, so
// a node's own floor still applies.
func TestServerMinimumSamplingIntervalIgnoresInvalidValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   float64
	}{
		{"negative", -1},
		{"nan", math.NaN()},
		{"infinity", math.Inf(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(MinimumSamplingInterval(tc.ms))
			srv.initHandlers()
			sess := srv.sb.NewSession()
			subID := createTestSubscription(t, srv, sess)
			ns := NewNodeNameSpace(srv, "sampling")
			node := NewVariableNode(ua.NewStringNodeID(ns.ID(), "floor"), "floor", int32(0))
			if err := node.SetAttribute(ua.AttributeIDMinimumSamplingInterval, DataValueFromValue(2000.0)); err != nil {
				t.Fatalf("SetAttribute: %v", err)
			}
			ns.AddNode(node)
			resp, err := srv.MonitoredItemService.CreateMonitoredItems(nil, &ua.CreateMonitoredItemsRequest{
				RequestHeader:  &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
				SubscriptionID: subID,
				ItemsToCreate: []*ua.MonitoredItemCreateRequest{{
					ItemToMonitor:       &ua.ReadValueID{NodeID: node.ID(), AttributeID: ua.AttributeIDValue},
					MonitoringMode:      ua.MonitoringModeReporting,
					RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1, SamplingInterval: 100},
				}},
			}, 0)
			if err != nil {
				t.Fatalf("CreateMonitoredItems: %v", err)
			}
			r := resp.(*ua.CreateMonitoredItemsResponse).Results[0]
			if r.StatusCode != ua.StatusOK || r.RevisedSamplingInterval != 2000 {
				t.Fatalf("result %+v, want StatusOK with revised interval 2000", r)
			}
		})
	}
}
