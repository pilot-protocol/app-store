package appstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// crashLoop records enough exits for id to spend its crash-loop budget.
func crashLoop(t *testing.T, sup *supervisor, id string) {
	t.Helper()
	for i := 0; i <= maxCrashesInWindow; i++ {
		sup.recordCrash(id)
	}
	if !sup.isSuspended(id) {
		t.Fatalf("%s not suspended after %d crashes", id, maxCrashesInWindow+1)
	}
}

// TestRescanUpgradeClearsCrashRecord: crash records are keyed by app ID, and
// the upgrade branch of rescanForNew kept s.crashes[id]. A v1 suspended for
// crash-looping made v2 report suspended from the start, and recordCrash's
// sticky suspended bit stopped v2 at its first exit. A new version starts
// with a clean record; the .suspended marker v1 left is removed when v2's
// supervise goroutine starts.
func TestRescanUpgradeClearsCrashRecord(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.app"
	appDir := writeAppDirWithVersion(t, root, id, "1.0.0")

	sup := newSupervisor(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     20 * 1e6,
	}, Deps{}, newQuietLogger(t))
	if fresh := sup.rescanForNew(); len(fresh) != 1 {
		t.Fatalf("initial discovery: fresh=%d, want 1", len(fresh))
	}
	crashLoop(t, sup, id)
	if err := os.WriteFile(filepath.Join(appDir, suspendedMarkerName), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	writeAppDirWithVersion(t, root, id, "2.0.0")
	fresh := sup.rescanForNew()
	if len(fresh) != 1 {
		t.Fatalf("upgrade not applied: fresh=%d, want 1", len(fresh))
	}
	if sup.isSuspended(id) {
		t.Error("v2 is suspended: it inherited v1's crash record")
	}
	if apps := sup.Apps(); len(apps) != 1 || apps[0].AppVersion != "2.0.0" || apps[0].Suspended {
		t.Errorf("Apps() = %+v, want one unsuspended 2.0.0", apps)
	}
	if sup.recordCrash(id) {
		t.Error("v2 suspended at its first exit")
	}

	// v2's supervise goroutine clears the marker as it starts. The context
	// is already canceled, so it returns before spawning anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sup.superviseOne(ctx, fresh[0])
	if _, err := os.Stat(filepath.Join(appDir, suspendedMarkerName)); !os.IsNotExist(err) {
		t.Errorf(".suspended marker left after v2's supervisor started, stat err=%v", err)
	}
}

// TestRescanReinstallClearsCrashRecord: rescanForGone dropped an uninstalled
// app from installed but kept its crash record, so a reinstall (same ID)
// came back suspended. The record goes with the install.
func TestRescanReinstallClearsCrashRecord(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.app"
	appDir := writeAppDirWithVersion(t, root, id, "1.0.0")

	sup := newSupervisor(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     20 * 1e6,
	}, Deps{}, newQuietLogger(t))
	if fresh := sup.rescanForNew(); len(fresh) != 1 {
		t.Fatalf("initial discovery: fresh=%d, want 1", len(fresh))
	}
	crashLoop(t, sup, id)

	if err := os.RemoveAll(appDir); err != nil {
		t.Fatal(err)
	}
	sup.rescanForGone()
	sup.mu.RLock()
	_, kept := sup.crashes[id]
	sup.mu.RUnlock()
	if kept {
		t.Error("crash record survived the uninstall")
	}

	writeAppDirWithVersion(t, root, id, "1.0.0")
	if fresh := sup.rescanForNew(); len(fresh) != 1 {
		t.Fatalf("reinstall not discovered: fresh=%d, want 1", len(fresh))
	}
	if sup.isSuspended(id) {
		t.Error("reinstalled app is suspended")
	}
	if apps := sup.Apps(); len(apps) != 1 || apps[0].Suspended {
		t.Errorf("Apps() = %+v, want one unsuspended app", apps)
	}
	if sup.recordCrash(id) {
		t.Error("reinstalled app suspended at its first exit")
	}
}
