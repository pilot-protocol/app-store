package extend

import (
	"errors"
	"strings"
	"testing"
)

// permFromList allows registration of exact (appID, primitive) pairs.
func permFromList(allowed map[string][]HookPoint) Permission {
	set := map[string]bool{}
	for app, points := range allowed {
		for _, p := range points {
			set[app+"::"+string(p)] = true
		}
	}
	return PermissionFunc(func(appID string, p HookPoint) bool {
		return set[appID+"::"+string(p)]
	})
}

func TestRuntimeRegisterPermitted(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, permFromList(map[string][]HookPoint{
		"io.pilot.wallet": {"wallet.pay.pre"},
	}))
	err := h.Register("io.pilot.wallet", Extension{
		Primitive: "wallet.pay.pre", Method: "wallet.hookPre",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := r.HooksFor("wallet.pay.pre"); len(got) != 1 || got[0].AppID != "io.pilot.wallet" {
		t.Errorf("hook not in registry: %+v", got)
	}
}

func TestRuntimeRegisterDenied(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, permFromList(map[string][]HookPoint{
		"io.pilot.wallet": {"wallet.pay.pre"}, // only this
	}))
	err := h.Register("io.pilot.wallet", Extension{
		Primitive: "send-message.pre", Method: "wallet.evilHook",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("want ErrPermissionDenied, got %v", err)
	}
	if got := r.HooksFor("send-message.pre"); len(got) != 0 {
		t.Errorf("denied hook leaked into registry: %+v", got)
	}
}

func TestRuntimeRegisterCannotImpersonate(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, AllowAll)
	err := h.Register("real-app", Extension{
		AppID:     "other-app", // tries to register for a different app
		Primitive: "x.pre",
		Method:    "m",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot register on behalf") {
		t.Errorf("want impersonation error, got %v", err)
	}
}

func TestRuntimeUnregisterTargeted(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, AllowAll)
	_ = h.Register("appx", Extension{Primitive: "x.pre", Method: "m1"})
	_ = h.Register("appx", Extension{Primitive: "x.pre", Method: "m2"})

	if err := h.Unregister("appx", "x.pre", "m1"); err != nil {
		t.Fatal(err)
	}
	got := r.HooksFor("x.pre")
	if len(got) != 1 || got[0].Method != "m2" {
		t.Errorf("after targeted unregister: %+v", got)
	}
}

func TestRuntimeUnregisterMalformedPoint(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, AllowAll)
	err := h.Unregister("appx", "bogus", "m")
	if err == nil || !strings.Contains(err.Error(), "malformed hook point") {
		t.Errorf("want malformed-hook-point error, got %v", err)
	}
}

func TestRuntimeListAll(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, AllowAll)
	_ = h.Register("appx", Extension{Primitive: "a.pre", Method: "m"})
	_ = h.Register("appy", Extension{Primitive: "b.post", Method: "n"})
	all := h.List("")
	if len(all) != 2 {
		t.Errorf("List(\"\"): %d hooks, want 2", len(all))
	}
	one := h.List("a.pre")
	if len(one) != 1 || one[0].AppID != "appx" {
		t.Errorf("List filtered: %+v", one)
	}
}

func TestNilPermissionDefaultsDenyAll(t *testing.T) {
	r := NewRegistry(newDispatcher().dispatch)
	h := NewDaemonHandler(r, nil)
	err := h.Register("appx", Extension{Primitive: "x.pre", Method: "m"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("nil Permission should default to DenyAll, got %v", err)
	}
}
