package server

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

func TestSessionBrokerBoundsUnactivatedSessions(t *testing.T) {
	sb := newSessionBroker(nil)
	sb.channelOpened(1)
	sb.channelOpened(2)
	for range maxUnactivatedSessionsPerChannel {
		if _, err := sb.newSessionOnChannel(1, time.Minute, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sb.newSessionOnChannel(1, time.Minute, nil, nil); err != ua.StatusBadTooManySessions {
		t.Fatalf("limit error = %v", err)
	}
	active, err := sb.newSessionOnChannel(2, time.Minute, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	active.activated.Store(true)
	sb.closeUnactivated(1)
	sb.closeUnactivated(2)
	if len(sb.s) != 1 || sb.Session(active.AuthTokenID) != active {
		t.Fatal("channel close did not remove only unactivated sessions")
	}
}

func TestSessionBrokerIdleTimeoutAndTouch(t *testing.T) {
	sb := newSessionBroker(nil)
	sb.channelOpened(1)
	sb.channelOpened(2)
	sess, err := sb.newSessionOnChannel(1, time.Second, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := sess.lastActivity
	if ok, _ := sb.touch(sess, start.Add(500*time.Millisecond)); !ok {
		t.Fatal("live session rejected")
	}
	// A request received earlier but handled later does not move the idle
	// clock back.
	if ok, _ := sb.touch(sess, start.Add(100*time.Millisecond)); !ok {
		t.Fatal("live session rejected")
	}
	if expired := sb.expired(start.Add(1200 * time.Millisecond)); len(expired) != 0 {
		t.Fatal("traffic did not extend the idle timeout")
	}
	if expired := sb.expired(start.Add(1500 * time.Millisecond)); len(expired) != 1 {
		t.Fatalf("expired %d sessions, want one", len(expired))
	}
	if ok, _ := sb.touch(sess, start.Add(1600*time.Millisecond)); ok {
		t.Fatal("expired session was resurrected")
	}
	other, _ := sb.newSessionOnChannel(2, time.Second, nil, nil)
	if ok, expired := sb.touch(other, other.lastActivity.Add(time.Second)); ok || expired != other {
		t.Fatal("expired request was accepted before the periodic reaper")
	}
}

func TestClosedChannelCannotRegisterLateSession(t *testing.T) {
	sb := newSessionBroker(nil)
	sb.channelOpened(1)
	sb.closeUnactivated(1)
	if _, err := sb.newSessionOnChannel(1, time.Minute, nil, nil); err != ua.StatusBadSecureChannelClosed {
		t.Fatalf("late CreateSession after channel close: %v", err)
	}
	if len(sb.s) != 0 {
		t.Fatal("closed channel leaked a late session")
	}
}
