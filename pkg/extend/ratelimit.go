package extend

import (
	"sync"
	"time"
)

// rateLimiter is a per-key token bucket used to bound how often the
// registry dispatches into any single app's hooks. A misbehaving or
// hostile app whose hooks fire on every primitive cannot turn the hook
// chain into a DoS amplifier: once its bucket is empty, further hook
// invocations are refused until it refills.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
	now     func() time.Time
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter allowing `burst` events instantly and
// `ratePerSec` sustained thereafter, per key.
func newRateLimiter(ratePerSec float64, burst int) *rateLimiter {
	return &rateLimiter{
		rate:    ratePerSec,
		burst:   float64(burst),
		now:     time.Now,
		buckets: map[string]*tokenBucket{},
	}
}

// allow reports whether one event for key may proceed now, consuming a
// token if so. Refills lazily based on elapsed wall-clock time.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	t := rl.now()
	b := rl.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: rl.burst, last: t}
		rl.buckets[key] = b
	}
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = t
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
