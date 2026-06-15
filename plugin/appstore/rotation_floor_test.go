package appstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRotateGenerations_KeepFloorIsOne covers the keep<1 guard: a
// non-positive keep is floored to 1, so the active log still rotates to .1.
func TestRotateGenerations_KeepFloorIsOne(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	if err := os.WriteFile(filepath.Join(dir, supervisorLogName), []byte("X"), 0o600); err != nil {
		t.Fatal(err)
	}
	sup.rotateGenerations(dir, 0) // keep<1 → floored to 1
	if _, err := os.Stat(filepath.Join(dir, supervisorLogName+".1")); err != nil {
		t.Errorf("expected supervisor.log.1 after floored rotation: %v", err)
	}
}
