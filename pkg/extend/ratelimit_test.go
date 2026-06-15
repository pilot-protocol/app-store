package extend

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// noopDispatch is a Dispatcher that echoes args back with no error.
func noopDispatch(_ context.Context, _, _ string, a HookArgs) (HookArgs, error) {
	return a, nil
}

// TestRun_RateLimitsPerApp asserts that once an app's burst budget is
// spent, Run refuses further hook dispatch with ErrRateLimited, and that
// the budget refills as the (injected) clock advances.
func TestRun_RateLimitsPerApp(t *testing.T) {
	t.Parallel()
	r := NewRegistry(noopDispatch)
	if err := r.Register(Extension{AppID: "io.spammer", Primitive: PreSendMessage, Method: "h"}); err != nil {
		t.Fatal(err)
	}
	// 1 token/sec, burst 3.
	r.SetRateLimit(1, 3)

	// Pin the clock so refill is deterministic.
	base := time.Unix(1_000_000, 0)
	now := base
	r.mu.Lock()
	r.limiter.now = func() time.Time { return now }
	r.mu.Unlock()

	ctx := context.Background()
	// First 3 calls consume the burst.
	for i := 0; i < 3; i++ {
		if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); err != nil {
			t.Fatalf("call %d should pass, got %v", i, err)
		}
	}
	// 4th call (no time elapsed) is rate-limited.
	if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th call err = %v, want ErrRateLimited", err)
	}
	// Advance 1s → exactly one token refills → one call passes, next fails.
	now = base.Add(time.Second)
	if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); err != nil {
		t.Fatalf("post-refill call should pass, got %v", err)
	}
	if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("call after refill drained err = %v, want ErrRateLimited", err)
	}
}

// TestRun_RateLimitIsPerApp confirms one app exhausting its budget does
// not block a different app's hooks.
func TestRun_RateLimitIsPerApp(t *testing.T) {
	t.Parallel()
	r := NewRegistry(noopDispatch)
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "h", Order: 1})
	_ = r.Register(Extension{AppID: "b", Primitive: PostRecvMessage, Method: "h", Order: 1})
	r.SetRateLimit(1, 1)
	now := time.Unix(2_000_000, 0)
	r.mu.Lock()
	r.limiter.now = func() time.Time { return now }
	r.mu.Unlock()

	ctx := context.Background()
	// Drain app "a".
	if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(ctx, PreSendMessage, HookArgs{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("app a should be limited, got %v", err)
	}
	// App "b" still has its own full budget.
	if _, err := r.Run(ctx, PostRecvMessage, HookArgs{}); err != nil {
		t.Fatalf("app b should not be limited, got %v", err)
	}
}

// TestRun_NoLimiterByDefault confirms back-compat: without SetRateLimit,
// many invocations all pass.
func TestRun_NoLimiterByDefault(t *testing.T) {
	t.Parallel()
	r := NewRegistry(noopDispatch)
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "h"})
	for i := 0; i < 1000; i++ {
		if _, err := r.Run(context.Background(), PreSendMessage, HookArgs{}); err != nil {
			t.Fatalf("unlimited registry should never rate-limit, got %v at %d", err, i)
		}
	}
}

// TestDaemonHandler_CapsDynamicRegistrations asserts an app cannot exceed
// maxDynamicRegistrationsPerApp dynamic hook registrations.
func TestDaemonHandler_CapsDynamicRegistrations(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(noopDispatch)
	h := NewDaemonHandler(reg, AllowAll)

	for i := 0; i < maxDynamicRegistrationsPerApp; i++ {
		err := h.Register("io.greedy", Extension{
			Primitive: PreSendMessage,
			Method:    fmt.Sprintf("m%d", i),
		})
		if err != nil {
			t.Fatalf("registration %d should succeed, got %v", i, err)
		}
	}
	// One past the cap must be refused.
	err := h.Register("io.greedy", Extension{Primitive: PreSendMessage, Method: "overflow"})
	if !errors.Is(err, ErrTooManyRegistrations) {
		t.Fatalf("over-cap registration err = %v, want ErrTooManyRegistrations", err)
	}
	// A different app is unaffected.
	if err := h.Register("io.modest", Extension{Primitive: PreSendMessage, Method: "m"}); err != nil {
		t.Fatalf("other app should still register, got %v", err)
	}
	// After unregistering one of greedy's hooks, it can register again.
	reg.UnregisterOne("io.greedy", PreSendMessage, "m0")
	if err := h.Register("io.greedy", Extension{Primitive: PreSendMessage, Method: "again"}); err != nil {
		t.Fatalf("after freeing a slot, registration should succeed, got %v", err)
	}
}
