package ipc

import (
	"strings"
	"testing"
)

func TestErrServerError_FormatsMessage(t *testing.T) {
	t.Parallel()
	e := &ErrServerError{Msg: "bad things"}
	if !strings.Contains(e.Error(), "bad things") {
		t.Errorf("Error() = %q", e.Error())
	}
	if !strings.Contains(e.Error(), "server error") {
		t.Errorf("Error() = %q, want 'server error' prefix", e.Error())
	}
}

func TestDispatcher_Methods(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("a", nil)
	d.Register("b", nil)
	d.Register("c", nil)
	got := d.Methods()
	if len(got) != 3 {
		t.Errorf("Methods len = %d, want 3", len(got))
	}
	// Ensure each is present (map iteration order is random).
	want := map[string]bool{"a": true, "b": true, "c": true}
	for _, m := range got {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
	}
}

func TestDispatcher_MethodsEmpty(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	if got := d.Methods(); len(got) != 0 {
		t.Errorf("Methods on empty dispatcher = %v", got)
	}
}
