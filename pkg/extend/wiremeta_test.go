package extend

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestGetMetaEmpty(t *testing.T) {
	m := GetMeta(HookArgs{})
	if m == nil {
		t.Fatal("GetMeta returned nil for empty args")
	}
	if len(m.TouchedBy) != 0 || len(m.Required) != 0 {
		t.Errorf("unexpected non-empty meta: %+v", m)
	}
}

func TestSetMetaRoundtrip(t *testing.T) {
	args := HookArgs{}
	in := &WireMeta{
		TouchedBy: []HookStamp{{AppID: "x", Primitive: "y.pre", At: time.Unix(1700000000, 0).UTC()}},
		Required:  []string{"x"},
	}
	SetMeta(args, in)
	out := GetMeta(args)
	if !reflect.DeepEqual(out, in) {
		t.Errorf("roundtrip diff:\n got %+v\nwant %+v", out, in)
	}
}

func TestGetMetaSurvivesJSONHop(t *testing.T) {
	// Simulates the meta crossing an IPC boundary: WireMeta gets
	// serialized to JSON, parsed back into map[string]any on the
	// other side. GetMeta must still reconstruct.
	original := &WireMeta{
		TouchedBy: []HookStamp{{AppID: "compress", Primitive: "send-message.pre", Details: map[string]any{"algo": "gzip"}}},
		Required:  []string{"compress"},
		Encoding:  []string{"gzip"},
	}
	b, _ := json.Marshal(original)
	var asMap map[string]any
	_ = json.Unmarshal(b, &asMap)

	args := HookArgs{metaKey: asMap}
	out := GetMeta(args)
	if len(out.TouchedBy) != 1 || out.TouchedBy[0].AppID != "compress" {
		t.Errorf("touched_by lost after JSON hop: %+v", out)
	}
	if out.Required[0] != "compress" || out.Encoding[0] != "gzip" {
		t.Errorf("required/encoding lost after JSON hop: %+v", out)
	}
}

func TestAddRequiredAndEncodingDedupOnStamp(t *testing.T) {
	args := HookArgs{}
	AddRequired(args, "a", "b", "a") // dup
	stampAndConsume(args, "appx", "send-message.pre", "v1", time.Unix(1, 0).UTC())
	m := GetMeta(args)
	if len(m.Required) != 2 || m.Required[0] != "a" || m.Required[1] != "b" {
		t.Errorf("required dedup failed: %v", m.Required)
	}
}

func TestSetDetailsContributesToStamp(t *testing.T) {
	args := HookArgs{}
	SetDetails(args, map[string]any{"contract_id": "abc", "amount": 100})
	stampAndConsume(args, "wallet", "send-message.pre", "v1", time.Unix(2, 0).UTC())
	m := GetMeta(args)
	if len(m.TouchedBy) != 1 || m.TouchedBy[0].Details["contract_id"] != "abc" {
		t.Errorf("details not on stamp: %+v", m.TouchedBy)
	}
	if _, leaked := args[detailsKey]; leaked {
		t.Errorf("__meta_details should be cleared after stamp")
	}
}

func TestStampClearsScratchKeys(t *testing.T) {
	args := HookArgs{}
	SetDetails(args, map[string]any{"k": "v"})
	AddRequired(args, "appx")
	AddEncoding(args, "gzip")
	stampAndConsume(args, "appx", "send-message.pre", "v1", time.Now().UTC())
	for _, k := range []string{detailsKey, requiredKey, encodingKey} {
		if _, exists := args[k]; exists {
			t.Errorf("scratch key %q not cleared", k)
		}
	}
}

func TestMissingRequired(t *testing.T) {
	meta := &WireMeta{Required: []string{"io.pilot.wallet", "io.pilot.compress"}}
	missing := MissingRequired(meta, []string{"io.pilot.compress"})
	if len(missing) != 1 || missing[0] != "io.pilot.wallet" {
		t.Errorf("missing: %v, want [io.pilot.wallet]", missing)
	}
}

func TestMissingRequiredNoneMissing(t *testing.T) {
	meta := &WireMeta{Required: []string{"x"}}
	if got := MissingRequired(meta, []string{"x", "y"}); len(got) != 0 {
		t.Errorf("got missing: %v, want none", got)
	}
}

func TestMissingRequiredNilMeta(t *testing.T) {
	if got := MissingRequired(nil, []string{"x"}); got != nil {
		t.Errorf("nil meta missing: %v", got)
	}
}

func TestStampCannotImpersonateApp(t *testing.T) {
	// A hook that tries to write its own bogus app id into a stamp
	// must not succeed. The registry's stampAndConsume takes app id
	// as a parameter — the hook's contribution is limited to Details.
	args := HookArgs{}
	// Hook tries to inject a stamp claiming to be from a different app.
	SetDetails(args, map[string]any{"app": "evil-impersonator"})
	stampAndConsume(args, "real-app", "x.pre", "v1", time.Unix(1, 0).UTC())
	m := GetMeta(args)
	if m.TouchedBy[0].AppID != "real-app" {
		t.Errorf("stamp AppID should be real-app, got %q", m.TouchedBy[0].AppID)
	}
	// Hook's "app" key landed in details, where it's clearly a hook
	// claim, not an authoritative identity.
	if m.TouchedBy[0].Details["app"] != "evil-impersonator" {
		t.Errorf("hook details preserved: %+v", m.TouchedBy[0].Details)
	}
}
