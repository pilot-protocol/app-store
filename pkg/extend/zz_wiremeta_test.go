package extend

import (
	"testing"
)

func TestGetMeta_AbsentReturnsEmpty(t *testing.T) {
	t.Parallel()
	got := GetMeta(HookArgs{})
	if got == nil {
		t.Fatal("GetMeta returned nil")
	}
	if got.Required != nil || len(got.TouchedBy) != 0 {
		t.Errorf("not empty: %+v", got)
	}
}

func TestGetMeta_NilValueReturnsEmpty(t *testing.T) {
	t.Parallel()
	got := GetMeta(HookArgs{"__meta": nil})
	if got == nil || len(got.TouchedBy) != 0 {
		t.Errorf("not empty: %+v", got)
	}
}

func TestGetMeta_StarReturnsAsIs(t *testing.T) {
	t.Parallel()
	m := &WireMeta{Required: []string{"app-1"}}
	got := GetMeta(HookArgs{"__meta": m})
	if got != m {
		t.Errorf("got %v, want pointer-equal to %v", got, m)
	}
}

func TestGetMeta_MapRoundtrips(t *testing.T) {
	t.Parallel()
	raw := map[string]any{
		"required": []any{"app-x"},
	}
	got := GetMeta(HookArgs{"__meta": raw})
	if len(got.Required) != 1 || got.Required[0] != "app-x" {
		t.Errorf("Required = %v", got.Required)
	}
}

func TestSetMeta_NilDeletesKey(t *testing.T) {
	t.Parallel()
	args := HookArgs{"__meta": &WireMeta{}}
	SetMeta(args, nil)
	if _, ok := args["__meta"]; ok {
		t.Error("expected key to be deleted")
	}
}

func TestSetMeta_StoresPointer(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	m := &WireMeta{Encoding: []string{"gzip"}}
	SetMeta(args, m)
	if args["__meta"] != m {
		t.Error("SetMeta did not stash pointer")
	}
}

func TestSetDetails_NilDeletes(t *testing.T) {
	t.Parallel()
	args := HookArgs{"__meta_details": map[string]any{"k": 1}}
	SetDetails(args, nil)
	if _, ok := args["__meta_details"]; ok {
		t.Error("expected details key to be deleted")
	}
}

func TestSetDetails_StoresMap(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	SetDetails(args, map[string]any{"k": "v"})
	got, _ := args["__meta_details"].(map[string]any)
	if got["k"] != "v" {
		t.Errorf("details not stored")
	}
}

func TestAddRequired_NoOpOnEmpty(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	AddRequired(args)
	if _, ok := args["__meta_required"]; ok {
		t.Error("empty AddRequired should not set key")
	}
}

func TestAddRequired_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	AddRequired(args, "a", "b")
	AddRequired(args, "c")
	got, _ := args["__meta_required"].([]string)
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestAddEncoding_NoOpOnEmpty(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	AddEncoding(args)
	if _, ok := args["__meta_encoding"]; ok {
		t.Error("empty AddEncoding should not set key")
	}
}

func TestAddEncoding_AppendsInOrder(t *testing.T) {
	t.Parallel()
	args := HookArgs{}
	AddEncoding(args, "gzip")
	AddEncoding(args, "br")
	got, _ := args["__meta_encoding"].([]string)
	if len(got) != 2 || got[0] != "gzip" || got[1] != "br" {
		t.Errorf("got %v", got)
	}
}

func TestMissingRequired_AllPresent(t *testing.T) {
	t.Parallel()
	missing := MissingRequired(&WireMeta{Required: []string{"a", "b"}}, []string{"a", "b", "c"})
	if missing != nil {
		t.Errorf("missing = %v, want nil", missing)
	}
}

func TestMissingRequired_SomeMissing(t *testing.T) {
	t.Parallel()
	missing := MissingRequired(&WireMeta{Required: []string{"a", "b", "c"}}, []string{"a"})
	if len(missing) != 2 {
		t.Errorf("missing = %v, want 2", missing)
	}
}

func TestMissingRequired_NilMeta(t *testing.T) {
	t.Parallel()
	if got := MissingRequired(nil, []string{"a"}); got != nil {
		t.Errorf("nil meta: got %v, want nil", got)
	}
}

func TestMissingRequired_EmptyRequired(t *testing.T) {
	t.Parallel()
	if got := MissingRequired(&WireMeta{}, []string{"a"}); got != nil {
		t.Errorf("empty required: got %v, want nil", got)
	}
}
