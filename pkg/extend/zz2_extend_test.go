package extend

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestRegister_EmptyAppID covers the app_id-required branch.
func TestRegister_EmptyAppID(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	err := r.Register(Extension{Primitive: PreSendMessage, Method: "m"})
	if err == nil || !strings.Contains(err.Error(), "app_id required") {
		t.Errorf("err = %v, want app_id required", err)
	}
}

// TestRegister_UnknownFlagType covers the unknown-flag-type branch.
func TestRegister_UnknownFlagType(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	err := r.Register(Extension{
		AppID:     "appx",
		Primitive: PreSendMessage,
		Method:    "m",
		AddsFlags: []FlagSpec{{Name: "--x", Type: "float"}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("err = %v, want unknown type error", err)
	}
}

// TestRegister_StableOrder covers the sort.SliceStable path: same-order
// entries are returned in registration order.
func TestRegister_StableOrder(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "m1", Order: 5})
	_ = r.Register(Extension{AppID: "b", Primitive: PreSendMessage, Method: "m2", Order: 5})
	hooks := r.HooksFor(PreSendMessage)
	if len(hooks) != 2 || hooks[0].Method != "m1" || hooks[1].Method != "m2" {
		t.Errorf("stable order broken: %+v", hooks)
	}
}

// TestAllRegistered_Empty covers the no-hooks-registered branch.
func TestAllRegistered_Empty(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	if got := r.AllRegistered(); len(got) != 0 {
		t.Errorf("AllRegistered on empty registry = %v", got)
	}
}

// TestAllRegistered_AcrossMultiplePoints covers the multi-point branch.
func TestAllRegistered_AcrossMultiplePoints(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "m"})
	_ = r.Register(Extension{AppID: "b", Primitive: PostRecvMessage, Method: "n"})
	got := r.AllRegistered()
	if len(got) != 2 {
		t.Errorf("AllRegistered = %d entries, want 2", len(got))
	}
}

// TestRun_CtxCanceledBeforeFirstHook covers the early ctx.Err() branch.
func TestRun_CtxCanceledBeforeFirstHook(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{AppID: "x", Primitive: PreSendMessage, Method: "m"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Run(ctx, PreSendMessage, HookArgs{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestRun_NilNextRetainsCurrent covers the "if next != nil" else branch.
func TestRun_NilNextRetainsCurrent(t *testing.T) {
	t.Parallel()
	d := newDispatcher()
	r := NewRegistry(d.dispatch)
	d.register("mutating", "h", func(a HookArgs) (HookArgs, error) {
		a["mutated"] = true
		return nil, nil // returns nil; current must be retained
	})
	_ = r.Register(Extension{AppID: "mutating", Primitive: PreSendMessage, Method: "h"})
	out, err := r.Run(context.Background(), PreSendMessage, HookArgs{"original": true})
	if err != nil {
		t.Fatal(err)
	}
	if out["original"] != true {
		t.Errorf("original args lost when hook returned nil: %+v", out)
	}
	// The hook mutated the clone — the mutation lands on the cloned
	// map but the stamp/meta should still record the call.
	meta := GetMeta(out)
	if len(meta.TouchedBy) != 1 || meta.TouchedBy[0].AppID != "mutating" {
		t.Errorf("stamp missing: %+v", meta.TouchedBy)
	}
}

// TestUnregisterOne_DropsTargetedKeepsRest covers the targeted-remove
// branch where the surviving entry stays in the right position.
func TestUnregisterOne_DropsTargetedKeepsRest(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "m1", Order: 1})
	_ = r.Register(Extension{AppID: "a", Primitive: PreSendMessage, Method: "m2", Order: 2})
	r.UnregisterOne("a", PreSendMessage, "m1")
	got := r.HooksFor(PreSendMessage)
	if len(got) != 1 || got[0].Method != "m2" {
		t.Errorf("UnregisterOne dropped wrong entry: %+v", got)
	}
}

// TestCloneArgs_NilReturnsEmpty covers the nil-input branch.
func TestCloneArgs_NilReturnsEmpty(t *testing.T) {
	t.Parallel()
	got := cloneArgs(nil)
	if got == nil {
		t.Error("cloneArgs(nil) returned nil")
	}
	if len(got) != 0 {
		t.Errorf("cloneArgs(nil) len = %d, want 0", len(got))
	}
}

// TestCloneArgs_Duplicates covers the populated-map branch.
func TestCloneArgs_Duplicates(t *testing.T) {
	t.Parallel()
	src := HookArgs{"a": 1, "b": "two"}
	dst := cloneArgs(src)
	if dst["a"] != 1 || dst["b"] != "two" {
		t.Errorf("clone missing keys: %+v", dst)
	}
	dst["a"] = 99
	if src["a"] != 1 {
		t.Errorf("clone aliased the source map")
	}
}

// TestWrap_EmptyCommandErrors covers the empty-cmd guard.
func TestWrap_EmptyCommandErrors(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	_, err := Wrap(context.Background(), r, "", nil,
		func(_ context.Context, a HookArgs) (HookArgs, error) { return a, nil })
	if err == nil || !strings.Contains(err.Error(), "empty command name") {
		t.Errorf("err = %v, want empty-command error", err)
	}
}

// TestWrap_NilArgsBecomesEmptyMap covers the args==nil normalize.
func TestWrap_NilArgsBecomesEmptyMap(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	var sawNil bool
	out, err := Wrap(context.Background(), r, "noop", nil,
		func(_ context.Context, a HookArgs) (HookArgs, error) {
			if a == nil {
				sawNil = true
			}
			return a, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if sawNil {
		t.Error("core saw nil args; Wrap should normalize to empty map")
	}
	if out == nil {
		t.Error("Wrap returned nil out")
	}
}

// TestWrap_CoreReturnsNilUsesTransformed covers the "result == nil"
// fallback branch.
func TestWrap_CoreReturnsNilUsesTransformed(t *testing.T) {
	t.Parallel()
	r := NewRegistry(newDispatcher().dispatch)
	out, err := Wrap(context.Background(), r, "x", HookArgs{"orig": "yes"},
		func(_ context.Context, a HookArgs) (HookArgs, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if out["orig"] != "yes" {
		t.Errorf("transformed args lost when core returned nil: %+v", out)
	}
}

// TestGetMeta_BadMarshalFallsBackEmpty exercises the json.Marshal
// failure branch of GetMeta (passing a channel-bearing value).
func TestGetMeta_BadMarshalFallsBackEmpty(t *testing.T) {
	t.Parallel()
	// A channel cannot be marshaled. GetMeta must catch that and
	// return an empty WireMeta rather than panic.
	args := HookArgs{metaKey: make(chan int)}
	got := GetMeta(args)
	if got == nil {
		t.Error("GetMeta returned nil")
	}
	if len(got.TouchedBy) != 0 {
		t.Errorf("expected empty meta, got: %+v", got)
	}
}

// TestGetMeta_BadUnmarshalFallsBackEmpty exercises the json.Unmarshal
// failure branch by passing a map whose value types mismatch the
// WireMeta struct.
func TestGetMeta_BadUnmarshalFallsBackEmpty(t *testing.T) {
	t.Parallel()
	args := HookArgs{metaKey: map[string]any{
		"required": "not-a-slice",
	}}
	got := GetMeta(args)
	if got == nil {
		t.Error("GetMeta returned nil")
	}
}

// TestAppendUnique_AllDuplicatesNoOp covers the "have all" branch.
func TestAppendUnique_AllDuplicatesNoOp(t *testing.T) {
	t.Parallel()
	dst := []string{"a", "b"}
	got := appendUnique(dst, "a", "b")
	if len(got) != 2 {
		t.Errorf("appendUnique with all dups: %v, want len 2", got)
	}
}

// TestAppendUnique_NoExisting covers the empty-dst branch.
func TestAppendUnique_NoExisting(t *testing.T) {
	t.Parallel()
	got := appendUnique(nil, "a", "b", "a")
	if len(got) != 2 {
		t.Errorf("appendUnique on nil dst: %v, want 2", got)
	}
}
