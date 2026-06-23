package manifest

import "testing"

// proc.exec is a known capability and accepts an absolute-path target.
func TestValidate_ProcExecAbsolutePath(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants = append(m.Grants, Grant{Cap: "proc.exec", Target: "/usr/local/bin/weathercli"})
	if errs := m.Validate(); len(errs) != 0 {
		t.Fatalf("proc.exec with an absolute path must validate, got: %v", errs)
	}
}

// proc.exec accepts a bare command name (resolved via PATH).
func TestValidate_ProcExecBareCommand(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{"gh", "python3", "my-tool", "ripgrep"} {
		m := mustValid(t)
		m.Grants = append(m.Grants, Grant{Cap: "proc.exec", Target: cmd})
		if errs := m.Validate(); len(errs) != 0 {
			t.Errorf("proc.exec %q must validate, got: %v", cmd, errs)
		}
	}
}

// A proc.exec target must name exactly one binary: no wildcard, no shell, no
// spaces, no path traversal. Each of these must be rejected.
func TestValidate_ProcExecRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()
	bad := []string{
		"*",                    // wildcard — "run anything" is never allowed
		"/usr/bin/*",           // path wildcard
		"sh -c 'rm -rf /'",     // shell string with spaces
		"foo;bar",              // command separator
		"foo|bar",              // pipe
		"foo`id`",              // command substitution
		"foo$(id)",             // command substitution
		"../../bin/evil",       // path traversal
		"/opt/../etc/cron.d/x", // traversal inside an absolute path
		"tool\nsecond",         // newline injection
	}
	for _, target := range bad {
		m := mustValid(t)
		m.Grants = append(m.Grants, Grant{Cap: "proc.exec", Target: target})
		if !hasErrorContaining(m.Validate(), "proc.exec") {
			t.Errorf("proc.exec target %q must be rejected, but validation passed", target)
		}
	}
}

// An empty proc.exec target hits the generic empty-target error (not the
// proc.exec-specific one), same as any other cap.
func TestValidate_ProcExecEmptyTarget(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants = append(m.Grants, Grant{Cap: "proc.exec", Target: "  "})
	if !hasErrorContaining(m.Validate(), "target must not be empty") {
		t.Errorf("empty proc.exec target should hit the empty-target error, got: %v", m.Validate())
	}
}

// Security boundary: proc.exec is NOT in the sideload allow-list, so a CLI app
// (which carries a proc.exec grant) can never be sideloaded — it must go through
// the reviewed catalogue. This pins that boundary against accidental widening.
func TestEnforceSideloadPolicy_RejectsProcExec(t *testing.T) {
	t.Parallel()
	if _, ok := SideloadAllowedCaps["proc.exec"]; ok {
		t.Fatal("proc.exec must NOT be in the sideload allow-list (it is catalogue-only)")
	}
	m := baseSideloadOK()
	m.Grants = append(m.Grants, Grant{Cap: "proc.exec", Target: "/usr/local/bin/tool"})
	if err := EnforceSideloadPolicy(m); err == nil {
		t.Fatal("sideload policy must reject a proc.exec grant")
	}
}
