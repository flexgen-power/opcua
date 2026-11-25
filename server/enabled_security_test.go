// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

// wireTap relays one client connection to the server and keeps a copy of what
// the server sends back. The uasc client reports an Error message from the
// server as a plain EOF, so a test that needs the status code the server put
// on the wire reads it here.
type wireTap struct {
	addr string
	done chan struct{} // closed when the server has closed its side
	mu   sync.Mutex
	recv bytes.Buffer
}

func (w *wireTap) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recv.Write(b)
}

func tapServer(t *testing.T, ss *secureServer) *wireTap {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	w := &wireTap{addr: "opc.tcp://" + l.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		client, err := l.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		srv, err := net.Dial("tcp", strings.TrimPrefix(ss.addr, "opc.tcp://"))
		if err != nil {
			return
		}
		defer srv.Close()
		go func() { _, _ = io.Copy(srv, client); _ = srv.Close() }()
		_, _ = io.Copy(client, io.TeeReader(srv, w))
	}()
	return w
}

// refusal returns the status code of the Error message the server ended the
// connection with.
func (w *wireTap) refusal(t *testing.T) ua.StatusCode {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not close the connection")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	const hdrlen = 8
	for b := w.recv.Bytes(); len(b) >= hdrlen; {
		size := int(binary.LittleEndian.Uint32(b[4:hdrlen]))
		require.True(t, size >= hdrlen && size <= len(b), "malformed message from the server")
		if string(b[:3]) == uacp.MessageTypeError {
			e := new(uacp.Error)
			_, err := e.Decode(b[hdrlen:size])
			require.NoError(t, err)
			return ua.StatusCode(e.ErrorCode)
		}
		b = b[size:]
	}
	t.Fatal("server closed the connection without an Error message")
	return ua.StatusOK
}

// openChannelAs asks the server, through a wireTap, for a secure channel under
// the given profile, which need not be one the server advertises.
func openChannelAs(t *testing.T, ctx context.Context, ss *secureServer, policyURI string, mode ua.MessageSecurityMode) (*uasc.SecureChannel, *wireTap, error) {
	t.Helper()
	ep := endpointFor(t, ctx, ss.addr, ua.MessageSecurityModeSignAndEncrypt)
	cert, key := genCert(t, "urn:gopcua:test:rawclient")
	cfg := &uasc.Config{
		SecurityPolicyURI: policyURI,
		SecurityMode:      mode,
		Certificate:       cert,
		LocalKey:          key,
		RemoteCertificate: ep.ServerCertificate,
		Thumbprint:        uapolicy.Thumbprint(ep.ServerCertificate),
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    3 * time.Second,
	}
	tap := tapServer(t, ss)
	conn, err := uacp.Dial(ctx, tap.addr)
	require.NoError(t, err)
	sc, err := uasc.NewSecureChannel(ss.addr, conn, cfg, make(chan error, 8))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	return sc, tap, sc.Open(ctx)
}

// A secure channel opens only under a profile the server has enabled. The
// policy is refused before the client certificate is looked at, so the server
// key is never used under a policy the server does not offer.
func TestOpenSecureChannelNeedsAnEnabledProfile(t *testing.T) {
	const (
		sign    = ua.MessageSecurityModeSign
		encrypt = ua.MessageSecurityModeSignAndEncrypt
	)
	cases := []struct {
		name   string
		policy string
		mode   ua.MessageSecurityMode
		want   ua.StatusCode
		// validated says whether the client certificate may reach the validator.
		validated bool
	}{
		{"Basic128Rsa15 SignAndEncrypt", ua.SecurityPolicyURIBasic128Rsa15, encrypt, ua.StatusBadSecurityPolicyRejected, false},
		{"Basic128Rsa15 Sign", ua.SecurityPolicyURIBasic128Rsa15, sign, ua.StatusBadSecurityPolicyRejected, false},
		{"Basic256 SignAndEncrypt", ua.SecurityPolicyURIBasic256, encrypt, ua.StatusBadSecurityPolicyRejected, false},
		{"Basic256 Sign", ua.SecurityPolicyURIBasic256, sign, ua.StatusBadSecurityPolicyRejected, false},
		{"Basic256Sha256 Sign", ua.SecurityPolicyURIBasic256Sha256, sign, ua.StatusBadSecurityModeRejected, true},
		{"Basic256Sha256 SignAndEncrypt", ua.SecurityPolicyURIBasic256Sha256, encrypt, ua.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var validated atomic.Int32
			ss := startSecureServer(t, server.ClientCertificateValidator(func([]byte) error {
				validated.Add(1)
				return nil
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, tap, err := openChannelAs(t, ctx, ss, tc.policy, tc.mode)
			if tc.want == ua.StatusOK {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, tc.want, tap.refusal(t))
			}
			require.Equal(t, tc.validated, validated.Load() > 0,
				"client certificate reached the validator: %d times", validated.Load())
		})
	}
}

// Clients read the endpoint list over a None channel before they can open a
// secured one, so discovery keeps working on a server with no None endpoint.
func TestDiscoveryOverNoneChannelWithOnlyASecuredProfile(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	eps, err := opcua.GetEndpoints(ctx, ss.addr)
	require.NoError(t, err)
	require.Len(t, eps, 1)
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, eps[0].SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, eps[0].SecurityMode)

	servers, err := opcua.FindServers(ctx, ss.addr)
	require.NoError(t, err)
	require.NotEmpty(t, servers)
}

// The enabled-profile check applies to the request that opens a channel; a
// renewal of a channel opened under an enabled profile still goes through.
func TestRenewalOfAnEnabledProfileStillWorks(t *testing.T) {
	ss := startSecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sc, _, err := openChannelAs(t, ctx, ss, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.NoError(t, err)
	require.NoError(t, sc.Renew(ctx))
	require.NoError(t, sc.Renew(ctx))

	// The renewed channel still carries requests.
	var got *ua.GetEndpointsResponse
	err = sc.SendRequest(ctx, &ua.GetEndpointsRequest{EndpointURL: ss.addr}, nil, func(r ua.Response) error {
		var ok bool
		got, ok = r.(*ua.GetEndpointsResponse)
		require.True(t, ok, "got %T", r)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, got.Endpoints, 1)
}
