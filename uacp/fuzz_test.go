// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"testing"

	"github.com/gopcua/opcua/ua"
)

// The transport decoders read bytes from a peer that has proved nothing yet.
// Whatever those bytes are, a decoder must return, with an error or without,
// and must not claim to have read more than it was given. `go test` runs the
// seeds; `go test -fuzz FuzzDecode ./uacp` searches for more.
func FuzzDecode(f *testing.F) {
	seed := func(v interface{}) {
		f.Helper()
		b, err := ua.Encode(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	seed(&Header{MessageType: MessageTypeHello, ChunkType: ChunkTypeFinal, MessageSize: 32})
	seed(&Hello{ReceiveBufSize: DefaultReceiveBufSize, SendBufSize: DefaultSendBufSize, MaxMessageSize: DefaultMaxMessageSize, MaxChunkCount: DefaultMaxChunkCount, EndpointURL: "opc.tcp://localhost:4840"})
	seed(&Acknowledge{ReceiveBufSize: DefaultReceiveBufSize, SendBufSize: DefaultSendBufSize, MaxMessageSize: DefaultMaxMessageSize, MaxChunkCount: DefaultMaxChunkCount})
	seed(&ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://localhost:4840"})
	seed(&Error{ErrorCode: uint32(ua.StatusBadTCPInternalError), Reason: "reason"})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})

	type decoder interface{ Decode([]byte) (int, error) }
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, d := range []decoder{new(Header), new(Hello), new(Acknowledge), new(ReverseHello), new(Error), new(Message)} {
			if n, err := d.Decode(b); err == nil && (n < 0 || n > len(b)) {
				t.Fatalf("%T read %d of %d bytes", d, n, len(b))
			}
		}
	})
}
