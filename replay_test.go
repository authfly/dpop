// Copyright 2026 Authfly
// SPDX-License-Identifier: Apache-2.0

package dpop_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/authfly/dpop"
)

func TestMemoryReplayCache(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	c := dpop.NewMemoryReplayCache(2).WithClock(clock)
	ctx := context.Background()
	use := func(jkt, jti string, ttl time.Duration) (bool, error) {
		return c.Use(ctx, jkt, jti, now.Add(ttl))
	}
	if r, err := use("k", "a", time.Minute); r || err != nil {
		t.Fatal(r, err)
	}
	if r, _ := use("k", "a", time.Minute); !r {
		t.Fatal("replay not detected")
	}
	if r, _ := use("k2", "a", time.Minute); r {
		t.Fatal("different jkt treated as replay")
	}
	if _, err := use("k", "b", time.Minute); !errors.Is(err, dpop.ErrCacheFull) {
		t.Fatalf("got %v, want ErrCacheFull", err)
	}
	now = now.Add(2 * time.Minute)
	if r, err := use("k", "a", time.Minute); r || err != nil {
		t.Fatal("expired entry not reusable:", r, err)
	}
	if c.Len() > 2 {
		t.Fatalf("Len = %d", c.Len())
	}
	c.WithClock(nil)
}

func TestMemoryReplayCacheConcurrent(t *testing.T) {
	c := dpop.NewMemoryReplayCache(0)
	exp := time.Now().Add(time.Minute)
	var mu sync.Mutex
	fresh := map[string]int{}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				jti := fmt.Sprint(i)
				r, err := c.Use(context.Background(), "k", jti, exp)
				if err != nil {
					t.Error(err)
					return
				}
				if !r {
					mu.Lock()
					fresh[jti]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	for jti, n := range fresh {
		if n != 1 {
			t.Fatalf("jti %s accepted %d times", jti, n)
		}
	}
	if len(fresh) != 200 {
		t.Fatalf("accepted %d distinct jti, want 200", len(fresh))
	}
}
