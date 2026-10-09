package server

import (
	"math"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

// createTestSubscription creates a subscription for sess through the service
// handler, as a client's CreateSubscription request would.
func createTestSubscription(t *testing.T, srv *Server, sess *session) uint32 {
	t.Helper()
	resp, err := srv.SubscriptionService.CreateSubscription(nil, &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		// An hour-long interval keeps run() from reaching keepalive or lifetime
		// handling, which would need a secure channel, while the test runs.
		RequestedPublishingInterval: float64(time.Hour / time.Millisecond),
		RequestedLifetimeCount:      10,
		RequestedMaxKeepAliveCount:  3,
	}, 0)
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	id := resp.(*ua.CreateSubscriptionResponse).SubscriptionID
	t.Cleanup(func() { srv.SubscriptionService.DeleteSubscription(id) })
	return id
}

// TestCreateSubscriptionNeverReissuesLiveID covers two clients with live
// subscriptions where one deletes its subscription and creates a new one. IDs
// derived from the live count gave the new subscription the other client's ID,
// replacing it in Subs, so the other client's publishes and monitored items
// followed the wrong subscription and either one's teardown deleted both.
func TestCreateSubscriptionNeverReissuesLiveID(t *testing.T) {
	srv := New()
	srv.initHandlers()
	clientA, clientB := srv.sb.NewSession(), srv.sb.NewSession()

	first := createTestSubscription(t, srv, clientA)
	second := createTestSubscription(t, srv, clientB)
	srv.SubscriptionService.DeleteSubscription(first)
	third := createTestSubscription(t, srv, clientA)

	if third == second {
		t.Fatalf("new subscription for client A was given client B's live ID %d", second)
	}
	if third == first {
		t.Fatalf("deleted ID %d was reissued", first)
	}
	srv.SubscriptionService.Mu.Lock()
	b := srv.SubscriptionService.Subs[second]
	srv.SubscriptionService.Mu.Unlock()
	if b == nil || b.Session != clientB {
		t.Fatalf("client B's subscription %d was replaced", second)
	}
}

// TestDeleteSubscriptionDoesNotHoldMuWhilePurgingItems covers the lock-order
// inversion between CreateMonitoredItems (MonitoredItemService.Mu, then
// SubscriptionService.Mu) and DeleteSubscription (SubscriptionService.Mu, then
// MonitoredItemService.Mu inside DeleteSub). The test holds
// MonitoredItemService.Mu as CreateMonitoredItems does and deletes a
// subscription; SubscriptionService.Mu must still become free, or the two
// deadlock and wedge the request dispatcher and ingest.
func TestDeleteSubscriptionDoesNotHoldMuWhilePurgingItems(t *testing.T) {
	srv := New()
	srv.initHandlers()
	id := createTestSubscription(t, srv, srv.sb.NewSession())

	srv.MonitoredItemService.Mu.Lock()
	deleted := make(chan struct{})
	go func() {
		defer close(deleted)
		srv.SubscriptionService.DeleteSubscription(id)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if srv.SubscriptionService.Mu.TryLock() {
			_, live := srv.SubscriptionService.Subs[id]
			srv.SubscriptionService.Mu.Unlock()
			if !live {
				break
			}
		}
		if time.Now().After(deadline) {
			srv.MonitoredItemService.Mu.Unlock()
			<-deleted
			t.Fatal("DeleteSubscription held SubscriptionService.Mu while waiting for MonitoredItemService.Mu")
		}
		time.Sleep(time.Millisecond)
	}
	srv.MonitoredItemService.Mu.Unlock()
	select {
	case <-deleted:
	case <-time.After(2 * time.Second):
		t.Fatal("DeleteSubscription did not finish once MonitoredItemService.Mu was free")
	}
}

func TestNextIDSkipsZeroAndLiveIDsOnWraparound(t *testing.T) {
	s := &SubscriptionService{Subs: map[uint32]*Subscription{1: {}, 2: {}}}
	s.lastID = math.MaxUint32 - 1

	got := []uint32{s.nextID(), s.nextID()}
	want := []uint32{math.MaxUint32, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nextID sequence = %v, want %v", got, want)
		}
	}
}
