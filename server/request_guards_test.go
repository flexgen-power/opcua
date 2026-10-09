package server

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

// unknownSession is a request header whose token names no session.
func unknownSession() *ua.RequestHeader {
	return &ua.RequestHeader{AuthenticationToken: ua.NewNumericNodeID(0, 424242)}
}

// Every request handler here runs on the single request dispatcher, which has no
// recover: a panic in one request takes the whole server, and ingest, down.

func TestRequestsWithAnUnknownSessionAreRejectedNotPanics(t *testing.T) {
	srv := New()
	srv.initHandlers()
	owner := srv.sb.NewSession()
	id := createTestSubscription(t, srv, owner)

	cases := map[string]func() (ua.Response, error){
		"CreateSubscription": func() (ua.Response, error) {
			return srv.SubscriptionService.CreateSubscription(nil, &ua.CreateSubscriptionRequest{RequestHeader: unknownSession()}, 0)
		},
		"DeleteSubscriptions": func() (ua.Response, error) {
			return srv.SubscriptionService.DeleteSubscriptions(nil, &ua.DeleteSubscriptionsRequest{RequestHeader: unknownSession(), SubscriptionIDs: []uint32{id}}, 0)
		},
		"CreateMonitoredItems": func() (ua.Response, error) {
			return srv.MonitoredItemService.CreateMonitoredItems(nil, &ua.CreateMonitoredItemsRequest{RequestHeader: unknownSession(), SubscriptionID: id}, 0)
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			if !errors.Is(err, ua.StatusBadSessionIDInvalid) {
				t.Fatalf("got err %v, want BadSessionIdInvalid", err)
			}
		})
	}
	srv.SubscriptionService.Mu.Lock()
	n := len(srv.SubscriptionService.Subs)
	srv.SubscriptionService.Mu.Unlock()
	if n != 1 {
		t.Fatalf("rejected requests must not create or delete subscriptions, have %d", n)
	}
}

// A client can name a monitored item the server has already purged, for example
// after its subscription was deleted or timed out.
func TestMonitoredItemRequestsForUnknownItemsReturnInvalidID(t *testing.T) {
	srv := New()
	srv.initHandlers()
	sess := srv.sb.NewSession()
	id := createTestSubscription(t, srv, sess)
	hdr := &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID}

	del, err := srv.MonitoredItemService.DeleteMonitoredItems(nil, &ua.DeleteMonitoredItemsRequest{RequestHeader: hdr, SubscriptionID: id, MonitoredItemIDs: []uint32{42}}, 0)
	if err != nil {
		t.Fatalf("DeleteMonitoredItems: %v", err)
	}
	if got := del.(*ua.DeleteMonitoredItemsResponse).Results[0]; got != ua.StatusBadMonitoredItemIDInvalid {
		t.Fatalf("DeleteMonitoredItems result %v, want BadMonitoredItemIdInvalid", got)
	}

	mode, err := srv.MonitoredItemService.SetMonitoringMode(nil, &ua.SetMonitoringModeRequest{RequestHeader: hdr, SubscriptionID: id, MonitoredItemIDs: []uint32{42}}, 0)
	if err != nil {
		t.Fatalf("SetMonitoringMode: %v", err)
	}
	if got := mode.(*ua.SetMonitoringModeResponse).Results[0]; got != ua.StatusBadMonitoredItemIDInvalid {
		t.Fatalf("SetMonitoringMode result %v, want BadMonitoredItemIdInvalid", got)
	}
}

// A zero publishing interval reached time.NewTicker as a zero duration, which
// panics in the subscription's goroutine.
func TestCreateSubscriptionRevisesAZeroPublishingInterval(t *testing.T) {
	srv := New()
	srv.initHandlers()
	sess := srv.sb.NewSession()
	resp, err := srv.SubscriptionService.CreateSubscription(nil, &ua.CreateSubscriptionRequest{
		RequestHeader:               &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		RequestedPublishingInterval: 0,
		RequestedLifetimeCount:      1000,
		RequestedMaxKeepAliveCount:  1000,
	}, 0)
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	created := resp.(*ua.CreateSubscriptionResponse)
	t.Cleanup(func() { srv.SubscriptionService.DeleteSubscription(created.SubscriptionID) })
	if created.RevisedPublishingInterval != minPublishingInterval {
		t.Fatalf("revised publishing interval %v, want %v", created.RevisedPublishingInterval, minPublishingInterval)
	}
	time.Sleep(5 * minPublishingInterval * time.Millisecond) // let run() tick
}

// Huge and infinite intervals overflowed to a negative duration, which also
// panics time.NewTicker.
func TestRevisePublishingIntervalBoundsEveryRequest(t *testing.T) {
	for requested, want := range map[float64]float64{
		0:                     minPublishingInterval,
		-5:                    minPublishingInterval,
		math.NaN():            minPublishingInterval,
		250:                   250,
		1e15:                  maxPublishingInterval,
		math.Inf(1):           maxPublishingInterval,
		math.Inf(-1):          minPublishingInterval,
		maxPublishingInterval: maxPublishingInterval,
	} {
		got := revisePublishingInterval(requested)
		if got != want {
			t.Fatalf("revisePublishingInterval(%v) = %v, want %v", requested, got, want)
		}
		if d := time.Millisecond * time.Duration(got); d <= 0 {
			t.Fatalf("revised interval %v ms still gives a non-positive ticker duration %v", got, d)
		}
	}
}

// CloseSession with DeleteSubscriptions set must delete the session's
// subscriptions rather than leave them running until their lifetime expires.
func TestCloseSessionDeletesItsSubscriptionsWhenAsked(t *testing.T) {
	srv := New()
	srv.initHandlers()
	closing, other := srv.sb.NewSession(), srv.sb.NewSession()
	gone := createTestSubscription(t, srv, closing)
	kept := createTestSubscription(t, srv, other)

	_, err := (&SessionService{srv}).CloseSession(nil, &ua.CloseSessionRequest{
		RequestHeader:       &ua.RequestHeader{AuthenticationToken: closing.AuthTokenID},
		DeleteSubscriptions: true,
	}, 0)
	if err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	srv.SubscriptionService.Mu.Lock()
	_, stillThere := srv.SubscriptionService.Subs[gone]
	_, otherThere := srv.SubscriptionService.Subs[kept]
	srv.SubscriptionService.Mu.Unlock()
	if stillThere {
		t.Fatalf("subscription %d of the closed session is still running", gone)
	}
	if !otherThere {
		t.Fatalf("another session's subscription %d was deleted", kept)
	}
}
