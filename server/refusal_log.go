// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"net"
	"sync"
	"time"
)

const (
	refusalWarnInterval = time.Minute
	refusalWarnHosts    = 1024
)

// refusalLog bounds the warnings a peer can cause by repeating a request the
// server refuses, which costs the peer nothing: one per remote host and
// interval. The zero value is ready to use.
type refusalLog struct {
	mu    sync.Mutex
	hosts map[string]*refusalCount
}

type refusalCount struct {
	quietUntil time.Time
	skipped    int
}

// allow reports whether a refusal from addr may be logged as a warning now,
// and how many from the same host were not since the last one that was.
func (r *refusalLog) allow(addr string, now time.Time) (bool, int) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.hosts[host]
	if c == nil {
		if len(r.hosts) >= refusalWarnHosts {
			for h, old := range r.hosts {
				if !now.Before(old.quietUntil) {
					delete(r.hosts, h)
				}
			}
		}
		// Hosts beyond the table stay quiet rather than grow it.
		if len(r.hosts) >= refusalWarnHosts {
			return false, 0
		}
		if r.hosts == nil {
			r.hosts = make(map[string]*refusalCount)
		}
		c = &refusalCount{}
		r.hosts[host] = c
	}
	if now.Before(c.quietUntil) {
		c.skipped++
		return false, 0
	}
	skipped := c.skipped
	c.quietUntil, c.skipped = now.Add(refusalWarnInterval), 0
	return true, skipped
}
