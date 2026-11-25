// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

// An OpenSecureChannel fits one chunk (Part 6, 6.7.2), and each chunk of one
// costs private-key work before the peer is known. A chunk that says more
// will follow is therefore refused when it arrives, not collected.
func TestOpenSecureChannelMustBeASingleChunk(t *testing.T) {
	const uri = ua.SecurityPolicyURIBasic256Sha256
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ep := endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeSignAndEncrypt)
	cert, key := genCert(t, "urn:gopcua:test:rawclient")
	serverKey, err := uapolicy.PublicKey(ep.ServerCertificate)
	require.NoError(t, err)
	algo, err := uapolicy.Asymmetric(uri, key, serverKey)
	require.NoError(t, err)

	// Correctly padded, signed and encrypted, so that only its chunk type can
	// be the reason it is refused.
	sec, err := uasc.NewAsymmetricSecurityHeader(uri, cert, uapolicy.Thumbprint(ep.ServerCertificate)).Encode()
	require.NoError(t, err)
	const blocks = 2
	hdr := append([]byte("OPNC"), make([]byte, 8)...)
	hdr = append(hdr, sec...)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(hdr)+blocks*algo.BlockSize()))
	tail := make([]byte, 8+16) // sequence header and the start of a body
	binary.LittleEndian.PutUint32(tail[0:], 1)
	binary.LittleEndian.PutUint32(tail[4:], 1)
	padding := blocks*algo.PlaintextBlockSize() - algo.SignatureLength() - len(tail) - 1
	for i := 0; i <= padding; i++ {
		tail = append(tail, byte(padding))
	}
	sig, err := algo.Signature(append(append([]byte{}, hdr...), tail...))
	require.NoError(t, err)
	ct, err := algo.Encrypt(append(tail, sig...))
	require.NoError(t, err)
	require.Len(t, ct, blocks*algo.BlockSize())

	conn, err := uacp.Dial(ctx, ss.addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write(append(hdr, ct...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	reply := make([]byte, 16)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "the server kept the connection open for more chunks")
	require.Equal(t, uacp.MessageTypeError, string(reply[:3]))
	require.Equal(t, ua.StatusBadTCPMessageTypeInvalid, ua.StatusCode(binary.LittleEndian.Uint32(reply[8:])))
}
