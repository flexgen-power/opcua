package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

func TestParseIndexRange(t *testing.T) {
	cases := []struct {
		in     string
		want   indexRange
		ok     bool
		status ua.StatusCode
	}{
		{in: "", ok: false, status: ua.StatusOK},
		{in: "17", want: indexRange{17, 17}, ok: true, status: ua.StatusOK},
		{in: "0", want: indexRange{0, 0}, ok: true, status: ua.StatusOK},
		{in: "0:9", want: indexRange{0, 9}, ok: true, status: ua.StatusOK},
		{in: "5:5", status: ua.StatusBadIndexRangeInvalid},
		{in: "9:0", status: ua.StatusBadIndexRangeInvalid},
		{in: "-1", status: ua.StatusBadIndexRangeInvalid},
		{in: "+1", status: ua.StatusBadIndexRangeInvalid},
		{in: "abc", status: ua.StatusBadIndexRangeInvalid},
		{in: "1:", status: ua.StatusBadIndexRangeInvalid},
		{in: ":1", status: ua.StatusBadIndexRangeInvalid},
		{in: "1:2:3", status: ua.StatusBadIndexRangeInvalid},
		{in: " 1", status: ua.StatusBadIndexRangeInvalid},
		{in: "0:1,2:3", status: ua.StatusBadIndexRangeInvalid},
		{in: "99999999999999999999", status: ua.StatusBadIndexRangeInvalid},
	}
	for _, c := range cases {
		got, ok, status := parseIndexRange(c.in)
		if status != c.status || ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseIndexRange(%q) = %v, %v, %v; want %v, %v, %v", c.in, got, ok, status, c.want, c.ok, c.status)
		}
	}
}

// cellVoltages models one 104-cell PT2 chunk as stored by opcua_interface: a
// native-integer array where element i is cell i.
func cellVoltages() []uint16 {
	v := make([]uint16, 104)
	for i := range v {
		v[i] = uint16(3300 + i)
	}
	return v
}

func arrayDataValue(v any, status ua.StatusCode) *ua.DataValue {
	src := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
		Value:           ua.MustVariant(v),
		Status:          status,
		SourceTimestamp: src,
		ServerTimestamp: src.Add(time.Second),
	}
}

func TestApplyIndexRange(t *testing.T) {
	full := cellVoltages()
	cases := []struct {
		name   string
		dv     *ua.DataValue
		rng    string
		want   any
		status ua.StatusCode
	}{
		{name: "single element", dv: arrayDataValue(full, ua.StatusOK), rng: "17", want: []uint16{3317}},
		{name: "span", dv: arrayDataValue(full, ua.StatusOK), rng: "0:9", want: full[0:10]},
		{name: "last element", dv: arrayDataValue(full, ua.StatusOK), rng: "103", want: []uint16{3403}},
		{name: "span past the end is truncated", dv: arrayDataValue(full, ua.StatusOK), rng: "100:200", want: full[100:]},
		{name: "start past the end", dv: arrayDataValue(full, ua.StatusOK), rng: "104", status: ua.StatusBadIndexRangeNoData},
		{name: "span starting past the end", dv: arrayDataValue(full, ua.StatusOK), rng: "200:300", status: ua.StatusBadIndexRangeNoData},
		{name: "malformed", dv: arrayDataValue(full, ua.StatusOK), rng: "abc", status: ua.StatusBadIndexRangeInvalid},
		{name: "reversed span", dv: arrayDataValue(full, ua.StatusOK), rng: "9:0", status: ua.StatusBadIndexRangeInvalid},
		{name: "multi-dimensional", dv: arrayDataValue(full, ua.StatusOK), rng: "0:1,0:1", status: ua.StatusBadIndexRangeInvalid},
		{name: "scalar", dv: arrayDataValue(int32(7), ua.StatusOK), rng: "0", status: ua.StatusBadIndexRangeNoData},
		{name: "int32 temperatures", dv: arrayDataValue([]int32{-5, 0, 21, 22}, ua.StatusOK), rng: "1:2", want: []int32{0, 21}},
		{name: "float array", dv: arrayDataValue([]float32{1.5, 2.5, 3.5}, ua.StatusOK), rng: "2", want: []float32{3.5}},
		{
			name:   "uncertain value is narrowed and keeps its status",
			dv:     arrayDataValue(full, ua.StatusUncertainNoCommunicationLastUsableValue),
			rng:    "3",
			want:   []uint16{3303},
			status: ua.StatusUncertainNoCommunicationLastUsableValue,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := *c.dv
			got := applyIndexRange(c.dv, c.rng)
			if got.Status != c.status {
				t.Fatalf("status = %v, want %v", got.Status, c.status)
			}
			if *c.dv != before {
				t.Fatal("the input DataValue was modified")
			}
			if c.want == nil {
				if got.Value != nil {
					t.Fatalf("value = %v, want none", got.Value.Value())
				}
				if got.EncodingMask&ua.DataValueValue != 0 {
					t.Fatal("encoding mask advertises a value that is not there")
				}
				if !got.ServerTimestamp.Equal(c.dv.ServerTimestamp) {
					t.Fatalf("server timestamp = %v, want %v", got.ServerTimestamp, c.dv.ServerTimestamp)
				}
				return
			}
			if !reflect.DeepEqual(got.Value.Value(), c.want) {
				t.Fatalf("value = %#v, want %#v", got.Value.Value(), c.want)
			}
			if got.Value.ArrayLength() != int32(reflect.ValueOf(c.want).Len()) {
				t.Fatalf("variant array length = %d, want %d", got.Value.ArrayLength(), reflect.ValueOf(c.want).Len())
			}
			if !got.SourceTimestamp.Equal(c.dv.SourceTimestamp) {
				t.Fatalf("source timestamp = %v, want %v", got.SourceTimestamp, c.dv.SourceTimestamp)
			}
		})
	}
}

// A namespace can hand back its stored DataValue. Ranging must not write
// through to it, or one client's per-cell read would truncate the array for
// every other reader and subscriber.
func TestApplyIndexRangeDoesNotAliasTheStoredArray(t *testing.T) {
	stored := arrayDataValue(cellVoltages(), ua.StatusOK)
	got := applyIndexRange(stored, "0:1")
	got.Value.Value().([]uint16)[0] = 0

	if n := len(stored.Value.Value().([]uint16)); n != 104 {
		t.Fatalf("stored array has %d elements, want 104", n)
	}
	if v := stored.Value.Value().([]uint16)[0]; v != 3300 {
		t.Fatalf("stored element 0 = %d, want 3300", v)
	}
}

// A value that is unavailable must report why, not an index-range status:
// opcua_interface publishes fields it has not yet received as
// BadWaitingForInitialData with no value.
func TestApplyIndexRangePassesUnavailableValuesThrough(t *testing.T) {
	cases := map[string]*ua.DataValue{
		"waiting for initial data": {
			EncodingMask: ua.DataValueStatusCode,
			Status:       ua.StatusBadWaitingForInitialData,
		},
		"bad with a stale value": arrayDataValue(cellVoltages(), ua.StatusBadNoCommunication),
		"good with no value": {
			EncodingMask: ua.DataValueStatusCode,
			Status:       ua.StatusOK,
		},
	}
	for name, dv := range cases {
		t.Run(name, func(t *testing.T) {
			if got := applyIndexRange(dv, "3"); got != dv {
				t.Fatalf("got %+v, want the input unchanged", got)
			}
		})
	}
	if got := applyIndexRange(nil, "3"); got != nil {
		t.Fatalf("nil DataValue became %+v", got)
	}
	whole := arrayDataValue(cellVoltages(), ua.StatusOK)
	if got := applyIndexRange(whole, ""); got != whole {
		t.Fatal("an empty IndexRange must return the whole value unchanged")
	}
}

// newIndexRangeServer returns a server with one 104-element array node and one
// scalar node, as a PT2 cell chunk would appear.
func newIndexRangeServer(t *testing.T) (*Server, *ua.NodeID, *ua.NodeID) {
	t.Helper()
	srv := New()
	srv.initHandlers()
	ns := NewNodeNameSpace(srv, "cells")
	arrayID := ua.NewStringNodeID(ns.ID(), "bms_1_rack_1_chunk_1.cell_voltage_mv")
	ns.AddNode(NewVariableNode(arrayID, "cell_voltage_mv", cellVoltages()))
	scalarID := ua.NewStringNodeID(ns.ID(), "bms_1_rack_1.soc")
	ns.AddNode(NewVariableNode(scalarID, "soc", float64(55)))
	return srv, arrayID, scalarID
}

func TestReadHonoursIndexRange(t *testing.T) {
	srv, arrayID, scalarID := newIndexRangeServer(t)
	attr := &AttributeService{srv}

	read := func(id *ua.NodeID, rng string) *ua.DataValue {
		t.Helper()
		resp, err := attr.Read(nil, &ua.ReadRequest{
			RequestHeader: &ua.RequestHeader{},
			NodesToRead:   []*ua.ReadValueID{{NodeID: id, AttributeID: ua.AttributeIDValue, IndexRange: rng}},
		}, 0)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		return resp.(*ua.ReadResponse).Results[0]
	}

	if dv := read(arrayID, "17"); dv.Status != ua.StatusOK || !reflect.DeepEqual(dv.Value.Value(), []uint16{3317}) {
		t.Fatalf("IndexRange 17: status %v value %v, want one element 3317", dv.Status, dv.Value)
	}
	if dv := read(arrayID, "0:9"); dv.Status != ua.StatusOK || len(dv.Value.Value().([]uint16)) != 10 {
		t.Fatalf("IndexRange 0:9: status %v value %v, want ten elements", dv.Status, dv.Value)
	}
	if dv := read(arrayID, "104"); dv.Status != ua.StatusBadIndexRangeNoData || dv.Value != nil {
		t.Fatalf("out of range: status %v value %v, want BadIndexRangeNoData and no value", dv.Status, dv.Value)
	}
	if dv := read(arrayID, "x"); dv.Status != ua.StatusBadIndexRangeInvalid || dv.Value != nil {
		t.Fatalf("malformed: status %v value %v, want BadIndexRangeInvalid and no value", dv.Status, dv.Value)
	}
	if dv := read(scalarID, "0"); dv.Status != ua.StatusBadIndexRangeNoData {
		t.Fatalf("scalar: status %v, want BadIndexRangeNoData", dv.Status)
	}
	if dv := read(arrayID, ""); len(dv.Value.Value().([]uint16)) != 104 {
		t.Fatalf("no IndexRange: got %d elements, want 104", len(dv.Value.Value().([]uint16)))
	}
	// The ranged reads above must not have changed what is stored.
	if dv := read(arrayID, ""); dv.Value.Value().([]uint16)[17] != 3317 {
		t.Fatal("stored array changed after ranged reads")
	}
}

func TestMonitoredItemsHonourIndexRange(t *testing.T) {
	srv, arrayID, _ := newIndexRangeServer(t)
	sess := srv.sb.NewSession()
	subID := createTestSubscription(t, srv, sess)

	item := func(handle uint32, rng string) *ua.MonitoredItemCreateRequest {
		return &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: arrayID, AttributeID: ua.AttributeIDValue, IndexRange: rng},
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: handle},
		}
	}
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader:  &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		SubscriptionID: subID,
		ItemsToCreate:  []*ua.MonitoredItemCreateRequest{item(1, "2:3"), item(2, "bad"), item(3, "200")},
	}, 0)
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	results := resp.(*ua.CreateMonitoredItemsResponse).Results
	if results[0].StatusCode != ua.StatusOK {
		t.Fatalf("valid range: status %v, want OK", results[0].StatusCode)
	}
	if results[1].StatusCode != ua.StatusBadIndexRangeInvalid || results[1].MonitoredItemID != 0 {
		t.Fatalf("malformed range: status %v id %d, want BadIndexRangeInvalid and no item", results[1].StatusCode, results[1].MonitoredItemID)
	}
	// A well-formed range past the current end is accepted: the array may grow,
	// and each notification reports NoData until it does.
	if results[2].StatusCode != ua.StatusOK {
		t.Fatalf("well-formed range past the end: status %v, want OK", results[2].StatusCode)
	}

	srv.MonitoredItemService.Mu.Lock()
	registered := len(srv.MonitoredItemService.Nodes[arrayID.String()])
	srv.MonitoredItemService.Mu.Unlock()
	if registered != 2 {
		t.Fatalf("%d items registered for the node, want 2 (the malformed one must not be)", registered)
	}

	srv.MonitoredItemService.ChangeNotification(arrayID)
	sub := srv.SubscriptionService.Subs[subID]
	sub.pendingMu.Lock()
	defer sub.pendingMu.Unlock()
	if n := sub.pending[1]; n == nil || !reflect.DeepEqual(n.Value.Value.Value(), []uint16{3302, 3303}) {
		t.Fatalf("handle 1 pending %+v, want elements 2:3", n)
	}
	if n := sub.pending[3]; n == nil || n.Value.Status != ua.StatusBadIndexRangeNoData {
		t.Fatalf("handle 3 pending %+v, want BadIndexRangeNoData", n)
	}
	if _, ok := sub.pending[2]; ok {
		t.Fatal("the rejected item produced a notification")
	}
}
