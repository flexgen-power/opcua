package server

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/gopcua/opcua/ua"
)

// indexRange is a parsed one-dimensional NumericRange: either a single index
// ("17") or an inclusive span ("0:9").
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/7.27
type indexRange struct {
	start, end int
}

// parseIndexRange parses the IndexRange of a ReadValueID. ok is false when the
// string is empty, meaning the whole value is wanted. A string that is not a
// valid one-dimensional range returns StatusBadIndexRangeInvalid.
//
// Multi-dimensional ranges ("0:1,2:3") are not supported and are reported as
// invalid rather than silently ignored.
func parseIndexRange(s string) (r indexRange, ok bool, status ua.StatusCode) {
	if s == "" {
		return indexRange{}, false, ua.StatusOK
	}
	if strings.Contains(s, ",") {
		return indexRange{}, false, ua.StatusBadIndexRangeInvalid
	}

	lo, hi, isSpan := strings.Cut(s, ":")
	start, err := parseIndex(lo)
	if err != nil {
		return indexRange{}, false, ua.StatusBadIndexRangeInvalid
	}
	if !isSpan {
		return indexRange{start: start, end: start}, true, ua.StatusOK
	}
	end, err := parseIndex(hi)
	// Part 4 §7.27: the upper bound of a span must be greater than the lower.
	if err != nil || end <= start {
		return indexRange{}, false, ua.StatusBadIndexRangeInvalid
	}
	return indexRange{start: start, end: end}, true, ua.StatusOK
}

// parseIndex accepts only plain non-negative decimal integers; strconv.Atoi
// alone would also accept a sign.
func parseIndex(s string) (int, error) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(s)
}

// applyIndexRange returns dv narrowed to the elements selected by indexRange.
//
// dv may be shared with the namespace's stored value, so it is never modified;
// a narrowed copy is returned instead. A DataValue that already carries a Bad
// status, or no value at all, is returned unchanged so that the reason the
// value is unavailable (BadWaitingForInitialData, for example) reaches the
// client instead of being masked by an index-range error. An Uncertain value
// is narrowed and keeps its status.
//
// Per Part 4 §5.10.2 and §7.27:
//   - a malformed range returns Bad_IndexRangeInvalid;
//   - a range on a scalar, or one that starts past the end of the array,
//     returns Bad_IndexRangeNoData;
//   - a span that runs past the end of the array returns the elements that do
//     exist.
//
// Sub-ranging String and ByteString scalars is not implemented and is reported
// as Bad_IndexRangeNoData.
func applyIndexRange(dv *ua.DataValue, indexRange string) *ua.DataValue {
	r, ok, status := parseIndexRange(indexRange)
	if status != ua.StatusOK {
		return indexRangeError(dv, status)
	}
	if !ok || dv == nil {
		return dv
	}
	if isBadStatus(dv.Status) || dv.Value == nil || dv.Value.Value() == nil {
		return dv
	}

	v := reflect.ValueOf(dv.Value.Value())
	if v.Kind() != reflect.Slice || len(dv.Value.ArrayDimensions()) > 1 {
		return indexRangeError(dv, ua.StatusBadIndexRangeNoData)
	}
	n := v.Len()
	if r.start >= n {
		return indexRangeError(dv, ua.StatusBadIndexRangeNoData)
	}
	end := min(r.end+1, n)

	// Copy the elements so the result never aliases the stored array.
	sub := reflect.MakeSlice(v.Type(), end-r.start, end-r.start)
	reflect.Copy(sub, v.Slice(r.start, end))
	variant, err := ua.NewVariant(sub.Interface())
	if err != nil {
		return indexRangeError(dv, ua.StatusBadInternalError)
	}

	out := *dv
	out.Value = variant
	out.EncodingMask |= ua.DataValueValue
	return &out
}

// isBadStatus reports whether the severity bits of s are Bad (Part 4 §7.39).
func isBadStatus(s ua.StatusCode) bool {
	return uint32(s)&0xC0000000 == 0x80000000
}

// indexRangeError returns a value-less DataValue carrying status, keeping the
// server timestamp of the original when there is one.
func indexRangeError(dv *ua.DataValue, status ua.StatusCode) *ua.DataValue {
	out := &ua.DataValue{
		EncodingMask: ua.DataValueStatusCode,
		Status:       status,
	}
	if dv != nil && dv.EncodingMask&ua.DataValueServerTimestamp != 0 {
		out.EncodingMask |= ua.DataValueServerTimestamp
		out.ServerTimestamp = dv.ServerTimestamp
	}
	return out
}
