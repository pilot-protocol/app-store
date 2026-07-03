package appkit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock lets limiter tests step wall-clock time deterministically.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_000_000, 0)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestNodeLimiter_AllowsThenBlocks exhausts a node's budget and asserts
// the next request is refused, while an unrelated node stays unaffected.
func TestNodeLimiter_AllowsThenBlocks(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	l := PerNodeLimiter(3, time.Minute)
	l.now = clk.now

	for i := 0; i < 3; i++ {
		if !l.Allow("node-a") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow("node-a") {
		t.Error("request 4 should be blocked")
	}
	if !l.Allow("node-b") {
		t.Error("independent node must have its own budget")
	}
}

// TestNodeLimiter_WindowSlides asserts the window is sliding, not fixed:
// capacity comes back exactly as old hits age out.
func TestNodeLimiter_WindowSlides(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	l := PerNodeLimiter(2, time.Minute)
	l.now = clk.now

	if !l.Allow("n") { // t=0
		t.Fatal("first request should pass")
	}
	clk.advance(30 * time.Second)
	if !l.Allow("n") { // t=30s
		t.Fatal("second request should pass")
	}
	if l.Allow("n") { // still 2 hits in window
		t.Error("third request inside window should be blocked")
	}
	clk.advance(31 * time.Second) // t=61s: hit at t=0 aged out, t=30s still in
	if !l.Allow("n") {
		t.Error("capacity should return once the oldest hit slides out")
	}
	if l.Allow("n") { // hits at 30s and 61s both within [1s, 61s]
		t.Error("window must slide, not reset wholesale")
	}
}

// TestNodeLimiter_SweepDropsStaleBuckets asserts the opportunistic sweep
// releases memory for nodes that went quiet.
func TestNodeLimiter_SweepDropsStaleBuckets(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	l := PerNodeLimiter(5, time.Second)
	l.now = clk.now

	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("node-%d", i))
	}
	clk.advance(5 * time.Second)
	l.Allow("node-fresh") // triggers the sweep

	l.mu.Lock()
	n := len(l.hits)
	l.mu.Unlock()
	if n != 1 {
		t.Errorf("stale buckets not swept: %d remain, want 1", n)
	}
}

// TestNodeLimiter_Concurrent hammers one limiter from many goroutines —
// run with -race this is the concurrency-safety check, and the total
// admitted must never exceed the budget.
func TestNodeLimiter_Concurrent(t *testing.T) {
	t.Parallel()
	l := PerNodeLimiter(50, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if l.Allow("shared") {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 50 {
		t.Errorf("allowed = %d, want exactly 50", allowed)
	}
}
