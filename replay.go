// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ReplayCache records proofs that have been seen so the same proof is not
// accepted twice (RFC 9449 §11.1). Use must atomically check and record the
// (jkt, jti) pair and report whether it was already present. Records may be
// dropped after expiresAt. Implementations must be safe for concurrent use.
//
// In a multi-instance deployment the cache must be shared (for example
// Redis SET NX with expiry); a per-process cache only protects one instance.
type ReplayCache interface {
	Use(ctx context.Context, jkt, jti string, expiresAt time.Time) (replayed bool, err error)
}

// ErrCacheFull is returned by MemoryReplayCache when it holds MaxEntries
// unexpired records. Verify fails closed in that case.
var ErrCacheFull = errors.New("dpop: replay cache full")

// MemoryReplayCache is an in-process ReplayCache with per-entry expiry and a
// hard size bound. The zero value is not usable; call NewMemoryReplayCache.
type MemoryReplayCache struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	max       int
	now       func() time.Time
	lastSweep time.Time
}

// NewMemoryReplayCache returns a cache holding at most maxEntries unexpired
// records. maxEntries <= 0 selects 100000.
func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &MemoryReplayCache{entries: make(map[string]time.Time), max: maxEntries, now: time.Now}
}

// WithClock sets the clock used to expire records and returns c. It should
// match Config.Now of the Verifier using the cache; nil restores time.Now.
// Call it before the cache is shared.
func (c *MemoryReplayCache) WithClock(now func() time.Time) *MemoryReplayCache {
	if now == nil {
		now = time.Now
	}
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
	return c
}

// Use implements ReplayCache.
func (c *MemoryReplayCache) Use(_ context.Context, jkt, jti string, expiresAt time.Time) (bool, error) {
	key := jkt + "\x00" + jti
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, ok := c.entries[key]; ok {
		if now.Before(exp) {
			return true, nil
		}
		delete(c.entries, key)
	}
	if len(c.entries) >= c.max || now.Sub(c.lastSweep) > time.Minute {
		c.sweep(now)
	}
	if len(c.entries) >= c.max {
		return false, ErrCacheFull
	}
	c.entries[key] = expiresAt
	return false, nil
}

// Len returns the number of records currently held (including expired ones
// not yet swept).
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *MemoryReplayCache) sweep(now time.Time) {
	for k, exp := range c.entries {
		if !now.Before(exp) {
			delete(c.entries, k)
		}
	}
	c.lastSweep = now
}
