package server

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

type blockingBrowseLogger struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *blockingBrowseLogger) Debug(msg string, _ ...any) {
	if strings.HasPrefix(msg, "BrowseRequest:") {
		l.once.Do(func() { close(l.entered) })
		<-l.release
	}
}

func (*blockingBrowseLogger) Error(string, ...any) {}
func (*blockingBrowseLogger) Info(string, ...any)  {}
func (*blockingBrowseLogger) Warn(string, ...any)  {}

func TestBrowseCompletesWhenAddNodeQueues(t *testing.T) {
	logger := &blockingBrowseLogger{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	srv := New(SetLogger(logger))
	ns := NewNodeNameSpace(srv, "dynamic")
	parent := ns.Objects()

	browseDone := make(chan struct{})
	go func() {
		defer close(browseDone)
		ns.Browse(&ua.BrowseDescription{
			NodeID:          parent.ID(),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.References),
			IncludeSubtypes: true,
			NodeClassMask:   uint32(ua.NodeClassAll),
		})
	}()

	select {
	case <-logger.entered:
	case <-time.After(time.Second):
		t.Fatal("Browse did not enter the handler")
	}

	writerStarted := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		close(writerStarted)
		child := NewVariableNode(ua.NewStringNodeID(ns.ID(), "dynamic.value"), "value", int32(1))
		ns.AddNode(child)
		parent.AddRef(child, RefTypeIDOrganizes, true)
	}()
	<-writerStarted

	// The pre-fix Browse held the namespace read lock while logging. Give
	// AddNode time to queue for the write lock before allowing Browse to call
	// Node; its nested read lock then deadlocked behind that queued writer.
	select {
	case <-writerDone:
	case <-time.After(100 * time.Millisecond):
	}
	close(logger.release)

	deadline := time.After(2 * time.Second)
	for browseDone != nil || writerDone != nil {
		select {
		case <-browseDone:
			browseDone = nil
		case <-writerDone:
			writerDone = nil
		case <-deadline:
			t.Fatal("Browse and AddNode deadlocked")
		}
	}
}

func TestNodeNameSpaceBrowseConcurrentAddRef(t *testing.T) {
	srv := New()
	ns := NewNodeNameSpace(srv, "dynamic")
	parent := ns.Objects()

	const additions = 200
	start := make(chan struct{})
	writerDone := make(chan struct{})
	browserDone := make(chan struct{})
	var browseErr error
	var once sync.Once

	go func() {
		defer close(writerDone)
		<-start
		for i := 0; i < additions; i++ {
			child := NewVariableNode(
				ua.NewStringNodeID(ns.ID(), fmt.Sprintf("dynamic.%d", i)),
				fmt.Sprintf("value_%d", i),
				int32(i),
			)
			ns.AddNode(child)
			parent.AddRef(child, RefTypeIDOrganizes, true)
		}
	}()

	go func() {
		defer close(browserDone)
		<-start
		for i := 0; i < additions; i++ {
			result := ns.Browse(&ua.BrowseDescription{
				NodeID:          parent.ID(),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
				IncludeSubtypes: false,
				NodeClassMask:   uint32(ua.NodeClassAll),
			})
			if result.StatusCode != ua.StatusOK {
				once.Do(func() { browseErr = result.StatusCode })
				return
			}
		}
	}()

	close(start)
	deadline := time.After(20 * time.Second)
	for writerDone != nil || browserDone != nil {
		select {
		case <-writerDone:
			writerDone = nil
		case <-browserDone:
			browserDone = nil
		case <-deadline:
			t.Fatal("concurrent Browse/AddRef did not complete")
		}
	}
	if browseErr != nil {
		t.Fatalf("browse failed: %v", browseErr)
	}

	result := ns.Browse(&ua.BrowseDescription{
		NodeID:          parent.ID(),
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		IncludeSubtypes: false,
		NodeClassMask:   uint32(ua.NodeClassAll),
	})
	if got := len(result.References); got != additions {
		t.Fatalf("references = %d, want %d", got, additions)
	}
}

func TestResponseWriteTimeoutOption(t *testing.T) {
	const timeout = 42 * time.Millisecond
	srv := New(ResponseWriteTimeout(timeout))
	if srv.cfg.responseWriteTimeout != timeout {
		t.Fatalf("response write timeout = %s, want %s", srv.cfg.responseWriteTimeout, timeout)
	}
}
