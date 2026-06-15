package extend

import (
	"context"
	"testing"
)

// TestSetRateLimit_DisableClearsLimiter covers the disable branch
// (non-positive rate/burst clears the limiter): a previously-enabled
// limiter is removed and Run stops rate-limiting.
func TestSetRateLimit_DisableClearsLimiter(t *testing.T) {
	t.Parallel()
	r := NewRegistry(noopDispatch)
	if err := r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "h"}); err != nil {
		t.Fatal(err)
	}
	r.SetRateLimit(1, 1) // enable, tiny budget
	r.SetRateLimit(0, 0) // disable again

	for i := 0; i < 50; i++ {
		if _, err := r.Run(context.Background(), PreSendMessage, HookArgs{}); err != nil {
			t.Fatalf("disabled limiter must not block (call %d): %v", i, err)
		}
	}
}
