package appstore

import (
	"testing"
	"time"
)

// TestNextBackoff_GrowsAndCaps asserts the verify-fail / crash-restart
// backoff doubles each step and saturates at the cap — i.e. it is not a
// fixed interval.
func TestNextBackoff_GrowsAndCaps(t *testing.T) {
	t.Parallel()
	const max = 30 * time.Second
	want := []time.Duration{
		2 * time.Second,  // 1 → 2
		4 * time.Second,  // 2 → 4
		8 * time.Second,  // 4 → 8
		16 * time.Second, // 8 → 16
		max,              // 16 → 32 capped to 30
		max,              // stays at cap
	}
	cur := time.Second
	for i, w := range want {
		cur = nextBackoff(cur, max)
		if cur != w {
			t.Fatalf("step %d: got %s, want %s", i, cur, w)
		}
	}

	// Strictly grows until the cap, never exceeds it.
	prev := time.Duration(0)
	c := time.Second
	for i := 0; i < 20; i++ {
		c = nextBackoff(c, max)
		if c < prev {
			t.Fatalf("backoff decreased at step %d: %s < %s", i, c, prev)
		}
		if c > max {
			t.Fatalf("backoff exceeded cap at step %d: %s > %s", i, c, max)
		}
		prev = c
	}
}
