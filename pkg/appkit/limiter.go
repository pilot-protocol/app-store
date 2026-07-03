package appkit

import (
	"sync"
	"time"
)

// NodeLimiter is a sliding-window rate limiter keyed by node identity
// (the Origin.Node text address). Each node gets an independent budget of
// maxReqs requests per window; a hostile or chatty remote node exhausts
// only its own bucket, never the app's whole surface.
//
// Concurrency-safe. Stale buckets are swept opportunistically on Allow
// (at most one full sweep per window) — no background goroutine, so a
// forgotten limiter never leaks.
type NodeLimiter struct {
	mu        sync.Mutex
	max       int
	window    time.Duration
	now       func() time.Time // injectable for tests
	hits      map[string][]time.Time
	lastSweep time.Time
}

// PerNodeLimiter builds a limiter allowing maxReqs requests per node
// within any sliding window of the given duration.
func PerNodeLimiter(maxReqs int, window time.Duration) *NodeLimiter {
	return &NodeLimiter{
		max:    maxReqs,
		window: window,
		now:    time.Now,
		hits:   map[string][]time.Time{},
	}
}

// Allow reports whether one more request from node may proceed now,
// recording it if so. A request is counted against the window ending at
// the moment of the call.
func (l *NodeLimiter) Allow(node string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	l.sweepLocked(t)
	cutoff := t.Add(-l.window)
	kept := pruneBefore(l.hits[node], cutoff)
	if len(kept) >= l.max {
		l.hits[node] = kept
		return false
	}
	l.hits[node] = append(kept, t)
	return true
}

// sweepLocked drops buckets whose every hit has aged out of the window.
// Runs at most once per window so a hot Allow path stays O(own bucket).
func (l *NodeLimiter) sweepLocked(t time.Time) {
	if t.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = t
	cutoff := t.Add(-l.window)
	for node, hits := range l.hits {
		if len(hits) == 0 || hits[len(hits)-1].Before(cutoff) {
			delete(l.hits, node)
		}
	}
}

// pruneBefore drops leading timestamps older than cutoff. Hits are
// appended in call order, so the slice is ascending and one scan from
// the front suffices.
func pruneBefore(hits []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(hits) && hits[i].Before(cutoff) {
		i++
	}
	return hits[i:]
}
