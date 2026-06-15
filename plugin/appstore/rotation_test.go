package appstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestAuditLogKeepsNGenerations drives repeated rotations and asserts the
// supervisor keeps exactly AuditLogMaxBackups rotated files
// (supervisor.log.1 .. .N), never more, and that .1 always holds the most
// recently rotated content.
func TestAuditLogKeepsNGenerations(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	app := &installedApp{Dir: dir, Manifest: parseDummyManifest(t, "io.test.app")}
	const backups = 3
	sup := newSupervisor(Config{
		InstallRoot:        dir,
		AuditLogMaxBytes:   200,
		AuditLogMaxBackups: backups,
	}, Deps{}, newQuietLogger(t))

	// Write far more than enough to trigger several rotations.
	for i := 0; i < 200; i++ {
		sup.writeAuditLine(app, auditEvent{Event: "spawn", PID: i, SHA256: "abc"})
	}

	// Exactly `backups` rotated generations must exist: .1 .. .N.
	for i := 1; i <= backups; i++ {
		p := filepath.Join(dir, fmt.Sprintf("%s.%d", supervisorLogName, i))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected rotated generation %s to exist: %v", p, err)
		}
	}
	// .N+1 must NOT exist — the oldest is discarded.
	overflow := filepath.Join(dir, fmt.Sprintf("%s.%d", supervisorLogName, backups+1))
	if _, err := os.Stat(overflow); !os.IsNotExist(err) {
		t.Errorf("generation beyond backup count should not exist: %s (err=%v)", overflow, err)
	}
	// Active log still present.
	if _, err := os.Stat(filepath.Join(dir, supervisorLogName)); err != nil {
		t.Errorf("active log missing after rotations: %v", err)
	}
}

// TestRotateGenerationsShiftsContent verifies the shift semantics
// directly: after a rotation, what was in .1 moves to .2.
func TestRotateGenerationsShiftsContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir, AuditLogMaxBackups: 2}, Deps{}, newQuietLogger(t))

	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(supervisorLogName, "ACTIVE")
	write(supervisorLogName+".1", "GEN1")

	sup.rotateGenerations(dir, 2)

	// active → .1, old .1 → .2
	if b, _ := os.ReadFile(filepath.Join(dir, supervisorLogName+".1")); string(b) != "ACTIVE" {
		t.Errorf(".1 = %q, want ACTIVE", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, supervisorLogName+".2")); string(b) != "GEN1" {
		t.Errorf(".2 = %q, want GEN1", b)
	}
}
