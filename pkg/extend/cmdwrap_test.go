package extend

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// wrapTestRegistry sets up a registry with the inProcessDispatcher
// already wired so tests can register hooks against any command.
func wrapTestRegistry(t *testing.T) (*Registry, *inProcessDispatcher) {
	t.Helper()
	d := newDispatcher()
	return NewRegistry(d.dispatch), d
}

func TestWrapNoHooksRunsCoreOnly(t *testing.T) {
	r, _ := wrapTestRegistry(t)
	called := false
	out, err := Wrap(context.Background(), r, "anything.cmd", HookArgs{"in": "x"},
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			called = true
			a["core_ran"] = true
			return a, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("core was not called")
	}
	if out["core_ran"] != true {
		t.Errorf("core result not threaded back: %+v", out)
	}
}

func TestWrapPreTransformsInputToCore(t *testing.T) {
	r, d := wrapTestRegistry(t)
	d.register("compress", "h", func(a HookArgs) (HookArgs, error) {
		a["data"] = "gzipped:" + a["data"].(string)
		return a, nil
	})
	_ = r.Register(Extension{AppID: "compress", Primitive: "send-message.pre", Method: "h"})

	seen := ""
	_, _ = Wrap(context.Background(), r, "send-message", HookArgs{"data": "hello"},
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			seen = a["data"].(string)
			return a, nil
		})
	if seen != "gzipped:hello" {
		t.Errorf("core saw %q, want %q", seen, "gzipped:hello")
	}
}

func TestWrapPreErrorSkipsCoreAndPost(t *testing.T) {
	r, d := wrapTestRegistry(t)
	d.register("guard", "h", func(a HookArgs) (HookArgs, error) {
		return nil, errors.New("forbidden")
	})
	d.register("post", "h", func(a HookArgs) (HookArgs, error) {
		t.Error("post must not run after pre error")
		return a, nil
	})
	_ = r.Register(Extension{AppID: "guard", Primitive: "send-message.pre", Method: "h"})
	_ = r.Register(Extension{AppID: "post", Primitive: "send-message.post", Method: "h"})

	coreRan := false
	_, err := Wrap(context.Background(), r, "send-message", nil,
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			coreRan = true
			return a, nil
		})
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("want forbidden error, got %v", err)
	}
	if coreRan {
		t.Error("core ran despite pre-hook error")
	}
}

func TestWrapCoreErrorSkipsPost(t *testing.T) {
	r, d := wrapTestRegistry(t)
	d.register("p", "h", func(a HookArgs) (HookArgs, error) {
		t.Error("post must not run when core errors")
		return a, nil
	})
	_ = r.Register(Extension{AppID: "p", Primitive: "send-message.post", Method: "h"})

	_, err := Wrap(context.Background(), r, "send-message", nil,
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			return nil, errors.New("core failed")
		})
	if err == nil || !strings.Contains(err.Error(), "core failed") {
		t.Errorf("want core error, got %v", err)
	}
}

func TestWrapPostSeesCoreOutput(t *testing.T) {
	r, d := wrapTestRegistry(t)
	var sawFromCore any
	d.register("audit", "h", func(a HookArgs) (HookArgs, error) {
		sawFromCore = a["core_out"]
		a["audited"] = true
		return a, nil
	})
	_ = r.Register(Extension{AppID: "audit", Primitive: "send-message.post", Method: "h"})

	out, _ := Wrap(context.Background(), r, "send-message", nil,
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			return HookArgs{"core_out": 42}, nil
		})
	if sawFromCore != 42 {
		t.Errorf("post saw %v from core, want 42", sawFromCore)
	}
	if out["audited"] != true {
		t.Errorf("audit transform not threaded: %+v", out)
	}
}

func TestWrapStacksPreHooksInOrder(t *testing.T) {
	r, d := wrapTestRegistry(t)
	d.register("a", "h", func(a HookArgs) (HookArgs, error) {
		a["data"] = "A:" + a["data"].(string)
		return a, nil
	})
	d.register("b", "h", func(a HookArgs) (HookArgs, error) {
		a["data"] = "B:" + a["data"].(string)
		return a, nil
	})
	_ = r.Register(Extension{AppID: "a", Primitive: "x.pre", Method: "h", Order: 1})
	_ = r.Register(Extension{AppID: "b", Primitive: "x.pre", Method: "h", Order: 2})

	out, _ := Wrap(context.Background(), r, "x", HookArgs{"data": "orig"},
		func(_ context.Context, a HookArgs) (HookArgs, error) { return a, nil })
	if out["data"] != "B:A:orig" {
		t.Errorf("stack order: %q", out["data"])
	}
}

func TestWrapAccumulatesMetaAcrossPreAndPost(t *testing.T) {
	r, d := wrapTestRegistry(t)
	d.register("wallet", "pre", func(a HookArgs) (HookArgs, error) {
		SetDetails(a, map[string]any{"sealed": true})
		AddRequired(a, "wallet")
		AddEncoding(a, "wallet/seal")
		return a, nil
	})
	d.register("audit", "post", func(a HookArgs) (HookArgs, error) { return a, nil })
	_ = r.Register(Extension{AppID: "wallet", Primitive: "send-message.pre", Method: "pre"})
	_ = r.Register(Extension{AppID: "audit", Primitive: "send-message.post", Method: "post"})

	out, _ := Wrap(context.Background(), r, "send-message", HookArgs{"data": "x"},
		func(_ context.Context, a HookArgs) (HookArgs, error) { return a, nil })

	m := GetMeta(out)
	if len(m.TouchedBy) != 2 {
		t.Fatalf("touched_by: %d, want 2 (pre + post)", len(m.TouchedBy))
	}
	if m.TouchedBy[0].AppID != "wallet" || m.TouchedBy[0].Primitive != "send-message.pre" {
		t.Errorf("first stamp: %+v", m.TouchedBy[0])
	}
	if m.TouchedBy[0].Details["sealed"] != true {
		t.Errorf("pre stamp lost details: %+v", m.TouchedBy[0])
	}
	if m.TouchedBy[1].AppID != "audit" {
		t.Errorf("second stamp app: %q", m.TouchedBy[1].AppID)
	}
	if len(m.Required) != 1 || m.Required[0] != "wallet" {
		t.Errorf("required: %v", m.Required)
	}
	if len(m.Encoding) != 1 || m.Encoding[0] != "wallet/seal" {
		t.Errorf("encoding: %v", m.Encoding)
	}
}

func TestWrapNilRegistryErrors(t *testing.T) {
	_, err := Wrap(context.Background(), nil, "x", nil, func(_ context.Context, a HookArgs) (HookArgs, error) { return a, nil })
	if err == nil {
		t.Error("expected error for nil registry")
	}
}

func TestWrapNilCoreErrors(t *testing.T) {
	r, _ := wrapTestRegistry(t)
	_, err := Wrap(context.Background(), r, "x", nil, nil)
	if err == nil {
		t.Error("expected error for nil core")
	}
}
