// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRefusalLogWarnsOncePerHostAndInterval(t *testing.T) {
	var r refusalLog
	now := time.Now()

	ok, skipped := r.allow("192.0.2.1:1000", now)
	require.True(t, ok)
	require.Zero(t, skipped)
	// A new connection from the same host is the same peer.
	for port := 1001; port < 1004; port++ {
		ok, _ = r.allow(fmt.Sprintf("192.0.2.1:%d", port), now.Add(time.Second))
		require.False(t, ok)
	}
	ok, _ = r.allow("[2001:db8::1]:1000", now)
	require.True(t, ok, "another host has its own allowance")

	ok, skipped = r.allow("192.0.2.1:1004", now.Add(refusalWarnInterval))
	require.True(t, ok)
	require.Equal(t, 3, skipped)
}

func TestRefusalLogIsBoundedInHosts(t *testing.T) {
	var r refusalLog
	now := time.Now()
	for i := 0; i < refusalWarnHosts; i++ {
		ok, _ := r.allow(fmt.Sprintf("host-%d:1", i), now)
		require.True(t, ok)
	}
	ok, _ := r.allow("one-more:1", now.Add(time.Second))
	require.False(t, ok)
	require.Len(t, r.hosts, refusalWarnHosts)

	// Hosts whose interval has passed make room.
	ok, _ = r.allow("one-more:1", now.Add(refusalWarnInterval))
	require.True(t, ok)
	require.Len(t, r.hosts, 1)
}
