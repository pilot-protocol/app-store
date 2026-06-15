package manifest

import "testing"

func TestExposesMethod(t *testing.T) {
	m := &Manifest{Exposes: []string{"a.read", "a.write"}}
	cases := map[string]bool{
		"a.read":  true,
		"a.write": true,
		"a.admin": false,
		"":        false,
	}
	for method, want := range cases {
		if got := m.ExposesMethod(method); got != want {
			t.Errorf("ExposesMethod(%q) = %v, want %v", method, got, want)
		}
	}
	// Empty exposes is fail-closed: nothing is callable.
	empty := &Manifest{}
	if empty.ExposesMethod("a.read") {
		t.Errorf("empty exposes should expose nothing")
	}
}

func TestHasGrant(t *testing.T) {
	m := &Manifest{Grants: []Grant{
		{Cap: "ipc.call", Target: "io.pilot.wallet.pay"},
		{Cap: "ipc.call", Target: "io.pilot.notes.*"},
		{Cap: "fs.read", Target: "*"},
	}}
	type tc struct {
		cap, target string
		want        bool
	}
	for _, c := range []tc{
		{"ipc.call", "io.pilot.wallet.pay", true},   // exact
		{"ipc.call", "io.pilot.wallet.refund", false}, // exact mismatch
		{"ipc.call", "io.pilot.notes.add", true},    // prefix.*
		{"ipc.call", "io.pilot.notes.list", true},   // prefix.*
		{"ipc.call", "io.pilot.notesX.add", false},  // prefix must end at dot
		{"fs.read", "anything.at.all", true},        // blanket *
		{"net.dial", "io.pilot.wallet.pay", false},  // cap mismatch
	} {
		if got := m.HasGrant(c.cap, c.target); got != c.want {
			t.Errorf("HasGrant(%q,%q) = %v, want %v", c.cap, c.target, got, c.want)
		}
	}
}

func TestMatchGrantTarget(t *testing.T) {
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"*", "x.y", true},
		{"x.y", "x.y", true},
		{"x.*", "x.y", true},
		{"x.*", "x.y.z", true},
		{"x.*", "xy.z", false}, // trailing dot kept → "xy.z" lacks "x." prefix
		{"x.y", "x.z", false},
	}
	for _, c := range cases {
		if got := matchGrantTarget(c.pattern, c.target); got != c.want {
			t.Errorf("matchGrantTarget(%q,%q) = %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}
