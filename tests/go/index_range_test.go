//go:build integration
// +build integration

package uatest2

import (
	"context"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestReadIndexRange reads elements of an array node over the wire with an
// IndexRange, so the narrowed Variant is encoded and decoded by a real client.
func TestReadIndexRange(t *testing.T) {
	ctx := context.Background()

	srv := startServer()
	defer srv.Close()

	time.Sleep(2 * time.Second)

	c, err := opcua.NewClient("opc.tcp://localhost:4840", opcua.SecurityMode(ua.MessageSecurityModeNone))
	require.NoError(t, err, "NewClient failed")
	require.NoError(t, c.Connect(ctx), "Connect failed")
	defer c.Close(ctx)

	id := ua.NewStringNodeID(1, "ro_array_uint16")
	tests := []struct {
		rng    string
		status ua.StatusCode
		want   interface{}
	}{
		{"", ua.StatusOK, []uint16{3300, 3301, 3302, 3303, 3304}},
		{"2", ua.StatusOK, []uint16{3302}},
		{"1:3", ua.StatusOK, []uint16{3301, 3302, 3303}},
		{"3:9", ua.StatusOK, []uint16{3303, 3304}},
		{"5", ua.StatusBadIndexRangeNoData, nil},
		{"3:1", ua.StatusBadIndexRangeInvalid, nil},
	}
	for _, tt := range tests {
		t.Run(tt.rng, func(t *testing.T) {
			resp, err := c.Read(ctx, &ua.ReadRequest{
				NodesToRead:        []*ua.ReadValueID{{NodeID: id, AttributeID: ua.AttributeIDValue, IndexRange: tt.rng}},
				TimestampsToReturn: ua.TimestampsToReturnBoth,
			})
			require.NoError(t, err, "Read failed")
			require.Equal(t, tt.status, resp.Results[0].Status)
			if tt.want == nil {
				// The client decodes an absent value as a null Variant.
				if v := resp.Results[0].Value; v != nil {
					require.Nil(t, v.Value())
				}
				return
			}
			require.Equal(t, tt.want, resp.Results[0].Value.Value())
		})
	}
}
