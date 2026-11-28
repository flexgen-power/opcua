// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"testing"

	"github.com/gopcua/opcua/ua"
)

// The chunk headers are read before a chunk is verified or decrypted, so they
// come from a peer that has proved nothing yet. Whatever the bytes are, a
// decoder must return, with an error or without, and must not claim to have
// read more than it was given. `go test` runs the seeds;
// `go test -fuzz FuzzDecodeHeaders ./uasc` searches for more.
func FuzzDecodeHeaders(f *testing.F) {
	seed := func(parts ...interface{}) {
		f.Helper()
		var all []byte
		for _, v := range parts {
			b, err := ua.Encode(v)
			if err != nil {
				f.Fatal(err)
			}
			all = append(all, b...)
		}
		f.Add(all)
	}
	seed(NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
		NewAsymmetricSecurityHeader(ua.SecurityPolicyURINone, nil, nil), NewSequenceHeader(1, 1))
	seed(NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
		NewAsymmetricSecurityHeader(ua.SecurityPolicyURIBasic256Sha256, make([]byte, 64), make([]byte, 20)))
	seed(NewHeader(MessageTypeMessage, ChunkTypeFinal, 7), NewSymmetricSecurityHeader(1), NewSequenceHeader(2, 2))
	seed(NewHeader(MessageTypeMessage, ChunkTypeIntermediate, 7), NewSymmetricSecurityHeader(1), NewSequenceHeader(3, 2))
	seed(NewHeader(MessageTypeCloseSecureChannel, ChunkTypeFinal, 7), NewSymmetricSecurityHeader(1), NewSequenceHeader(4, 3))
	f.Add([]byte{})
	f.Add([]byte("MSGA\x10\x00\x00\x00\x07\x00\x00\x00\xff\xff\xff\xff"))

	type decoder interface{ Decode([]byte) (int, error) }
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, d := range []decoder{
			new(Header), new(AsymmetricSecurityHeader), new(SymmetricSecurityHeader), new(SequenceHeader),
			new(MessageHeader), new(MessageChunk), new(MessageAbort),
		} {
			if n, err := d.Decode(b); err == nil && (n < 0 || n > len(b)) {
				t.Fatalf("%T read %d of %d bytes", d, n, len(b))
			}
		}
	})
}
