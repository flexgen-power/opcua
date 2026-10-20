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

// TestReadNonValueAttribute_AccessLevelValueOnly verifies that a Variable whose
// AccessLevel denies CurrentRead still exposes its non-Value attributes
// (BrowseName, NodeClass, DisplayName, …) on Read, while the Value attribute
// itself remains access-gated.
//
// OPC UA Part 3 §5.6.2 defines AccessLevel/UserAccessLevel as Variable-class
// attributes describing how the *Value* attribute may be accessed. Access to
// the other attributes is not governed by AccessLevel; a Read of them returns
// its own operation-level StatusCode per the Read Service (Part 4 §5.10.2).
// Gating every attribute on CurrentRead therefore violates the spec and makes a
// read-protected node un-browsable (a client cannot even resolve its
// BrowseName or NodeClass).
//
// This is the read-side counterpart to the non-Value *write* behavior already
// covered by tests/go/write_nonvalue_attribute_test.go, whose documentation
// states: "AccessLevel governs the Value attribute only."
func TestReadNonValueAttribute_AccessLevelValueOnly(t *testing.T) {
	srv := New()
	srv.initHandlers()
	ns := NewNodeNameSpace(srv, "urn:test:accesslevel")

	nodeID := ua.NewStringNodeID(ns.ID(), "no-read")
	n := NewVariableNode(nodeID, "NoRead", func() *ua.DataValue {
		return DataValueFromValue(int32(42))
	})
	// AccessLevel = CurrentWrite only. CurrentRead is not set, so
	// Node.Access(CurrentRead) is false. Stored as uint8 to match the type
	// Node.Access asserts when it reads the attribute back.
	n.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(uint8(ua.AccessLevelTypeCurrentWrite)))
	ns.AddNode(n)

	// Non-Value attributes must remain readable regardless of AccessLevel.
	for _, attr := range []struct {
		name string
		id   ua.AttributeID
	}{
		{"BrowseName", ua.AttributeIDBrowseName},
		{"NodeClass", ua.AttributeIDNodeClass},
		{"DisplayName", ua.AttributeIDDisplayName},
	} {
		dv := ns.Attribute(nodeID, attr.id)
		if dv.Status == ua.StatusBadUserAccessDenied {
			t.Errorf("read of non-Value attribute %s returned Bad_UserAccessDenied; "+
				"AccessLevel must gate the Value attribute only", attr.name)
		}
	}

	// The Value attribute stays access-gated.
	if dv := ns.Attribute(nodeID, ua.AttributeIDValue); dv.Status != ua.StatusBadUserAccessDenied {
		t.Errorf("read of Value attribute returned status %v; want Bad_UserAccessDenied", dv.Status)
	}
}
