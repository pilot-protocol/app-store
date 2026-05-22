package extend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// inProcessDispatcher returns a Dispatcher that runs hooks via callbacks
// registered against (appID, method). Lets the tests prove the chain
// semantics without spinning up real IPC.
type inProcessDispatcher struct {
	mu       sync.Mutex
	handlers map[string]func(HookArgs) (HookArgs, error)
}

func newDispatcher() *inProcessDispatcher {
	return &inProcessDispatcher{handlers: map[string]func(HookArgs) (HookArgs, error){}}
}

func (d *inProcessDispatcher) register(appID, method string, fn func(HookArgs) (HookArgs, error)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[appID+"::"+method] = fn
}

func (d *inProcessDispatcher) dispatch(_ context.Context, appID, method string, args HookArgs) (HookArgs, error) {
	d.mu.Lock()
	fn, ok := d.handlers[appID+"::"+method]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no handler: %s.%s", appID, method)
	}
	return fn(args)
}

func TestRegisterRejectsMalformedHookPoint(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	cases := []string{
		"bogus",                 // no phase
		"send-message",          // no phase
		"send-message.middle",   // wrong phase
		"",                      // empty
		".pre",                  // empty command
		"send-message..pre",     // empty segment
		"Send-Message.pre",      // uppercase
		"send message.pre",      // whitespace in segment
	}
	for _, p := range cases {
		err := r.Register(Extension{AppID: "x", Primitive: HookPoint(p), Method: "m"})
		if err == nil || !strings.Contains(err.Error(), "malformed hook point") {
			t.Errorf("primitive %q: want malformed-hook-point error, got %v", p, err)
		}
	}
}

func TestRegisterAcceptsOpenCommandSpace(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	// Any shape-valid hook point is accepted, even ones the daemon
	// doesn't (yet) wrap. They become inert until a wrapper appears.
	cases := []string{
		"send-message.pre",       // daemon built-in
		"send-message.post",      // daemon built-in
		"recv.post",              // daemon built-in
		"wallet.pay.pre",         // app-defined command
		"memories.recall.post",   // another app's command
		"appstore.install.pre",   // pilotctl subcommand
		"compress.gzip.pre",      // anticipated, no app registered yet
	}
	for _, p := range cases {
		err := r.Register(Extension{AppID: "x", Primitive: HookPoint(p), Method: "m"})
		if err != nil {
			t.Errorf("primitive %q: rejected: %v", p, err)
		}
	}
}

func TestRegisterRejectsEmptyMethod(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	err := r.Register(Extension{AppID: "x", Primitive: PreSendMessage, Method: ""})
	if err == nil || !strings.Contains(err.Error(), "method required") {
		t.Errorf("want method-required error, got %v", err)
	}
}

func TestRegisterRejectsMalformedFlag(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	err := r.Register(Extension{
		AppID:     "x",
		Primitive: PreSendMessage,
		Method:    "m",
		AddsFlags: []FlagSpec{{Name: "paywall", Type: "string"}}, // missing --
	})
	if err == nil || !strings.Contains(err.Error(), "--") {
		t.Errorf("want flag-format error, got %v", err)
	}
}

func TestHookChainTransformsArgsInOrder(t *testing.T) {
	d := newDispatcher()
	r := NewRegistry(d.dispatch)

	// Two apps both hook PreSendMessage. App A (order=1) prefixes
	// "data" with "A:", app B (order=2) prefixes with "B:". Chain
	// result should be "B:A:original".
	d.register("appA", "hookA", func(a HookArgs) (HookArgs, error) {
		a["data"] = "A:" + a["data"].(string)
		return a, nil
	})
	d.register("appB", "hookB", func(a HookArgs) (HookArgs, error) {
		a["data"] = "B:" + a["data"].(string)
		return a, nil
	})

	if err := r.Register(Extension{AppID: "appA", Primitive: PreSendMessage, Method: "hookA", Order: 1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(Extension{AppID: "appB", Primitive: PreSendMessage, Method: "hookB", Order: 2}); err != nil {
		t.Fatal(err)
	}

	out, err := r.Run(context.Background(), PreSendMessage, HookArgs{"data": "original"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out["data"] != "B:A:original" {
		t.Errorf("chain order: %q, want %q", out["data"], "B:A:original")
	}
}

func TestHookErrorAbortsChain(t *testing.T) {
	d := newDispatcher()
	r := NewRegistry(d.dispatch)

	d.register("first", "h", func(a HookArgs) (HookArgs, error) {
		a["touched_first"] = true
		return a, nil
	})
	d.register("middle", "h", func(a HookArgs) (HookArgs, error) {
		return nil, errors.New("intentional fail")
	})
	d.register("last", "h", func(a HookArgs) (HookArgs, error) {
		a["touched_last"] = true
		return a, nil
	})

	for _, e := range []Extension{
		{AppID: "first", Primitive: PreSendMessage, Method: "h", Order: 1},
		{AppID: "middle", Primitive: PreSendMessage, Method: "h", Order: 2},
		{AppID: "last", Primitive: PreSendMessage, Method: "h", Order: 3},
	} {
		if err := r.Register(e); err != nil {
			t.Fatal(err)
		}
	}

	out, err := r.Run(context.Background(), PreSendMessage, HookArgs{})
	if err == nil || !strings.Contains(err.Error(), "intentional fail") {
		t.Errorf("want error, got %v", err)
	}
	if out["touched_first"] != true {
		t.Error("first hook should have run")
	}
	if out["touched_last"] == true {
		t.Error("last hook must not have run after middle errored")
	}
}

func TestFlagsForUnion(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{
		AppID: "wallet", Primitive: PreSendMessage, Method: "h",
		AddsFlags: []FlagSpec{{Name: "--paywall", Type: "string", Help: "lock"}},
	})
	_ = r.Register(Extension{
		AppID: "compress", Primitive: PreSendMessage, Method: "h",
		AddsFlags: []FlagSpec{{Name: "--gzip", Type: "bool"}},
	})

	flags := r.FlagsFor(PreSendMessage)
	if len(flags) != 2 {
		t.Fatalf("flags: %d, want 2", len(flags))
	}
	names := map[string]bool{flags[0].Name: true, flags[1].Name: true}
	if !names["--paywall"] || !names["--gzip"] {
		t.Errorf("flag names: %v", names)
	}
}

func TestUnregisterRemovesAllAppHooks(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{AppID: "wallet", Primitive: PreSendMessage, Method: "pre"})
	_ = r.Register(Extension{AppID: "wallet", Primitive: PostRecvMessage, Method: "post"})
	_ = r.Register(Extension{AppID: "other", Primitive: PreSendMessage, Method: "x"})

	r.Unregister("wallet")

	if got := len(r.HooksFor(PreSendMessage)); got != 1 {
		t.Errorf("pre after unregister wallet: %d hooks, want 1 (other)", got)
	}
	if got := len(r.HooksFor(PostRecvMessage)); got != 0 {
		t.Errorf("post after unregister wallet: %d hooks, want 0", got)
	}
}

func TestRunIsolatesArgsBetweenHooks(t *testing.T) {
	// A misbehaving hook should not be able to mutate args in a way
	// that's visible to its predecessors retroactively. The registry
	// passes each hook a clone.
	d := newDispatcher()
	r := NewRegistry(d.dispatch)

	d.register("noisy", "h", func(a HookArgs) (HookArgs, error) {
		a["secret"] = "leaked"
		return a, nil // returned, fine — chain accumulates
	})

	originalArgs := HookArgs{"data": "x"}
	out, err := r.Run(context.Background(), PreSendMessage, originalArgs)
	if err == nil {
		// We didn't register an extension yet, so no chain ran.
		// Add it and re-run.
		_ = r.Register(Extension{AppID: "noisy", Primitive: PreSendMessage, Method: "h"})
		out, err = r.Run(context.Background(), PreSendMessage, originalArgs)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := originalArgs["secret"]; leaked {
		t.Error("hook mutated caller's args map")
	}
	if out["secret"] != "leaked" {
		t.Error("hook's return should still be visible in chain output")
	}
}

func TestRunWithNoDispatcherErrorsOnAnyHook(t *testing.T) {
	r := NewRegistry(nil) // intentionally nil — defense path
	_ = r.Register(Extension{AppID: "x", Primitive: PreSendMessage, Method: "h"})
	_, err := r.Run(context.Background(), PreSendMessage, HookArgs{})
	if err == nil {
		t.Error("expected error from nil dispatcher")
	}
}
