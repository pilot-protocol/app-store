package appstore

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStartWarnsOnPlaceholderCatalogPubkey is the RC-prep guard: a
// production build with all-zeros EmbeddedCatalogPubkey must surface
// a loud WARNING at Start so the dev-mode trust state can't be
// confused with a real catalog anchor. The default Config{} path
// hits this; a Config with a non-zero CatalogPubkey must NOT.
func TestStartWarnsOnPlaceholderCatalogPubkey(t *testing.T) {
	t.Run("placeholder (all-zeros) → warns", func(t *testing.T) {
		var buf strings.Builder
		s := NewService(Config{
			CataloguePublisher: testCatPub,
			InstallRoot:        t.TempDir(),
			Logger:             log.New(&buf, "", 0),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Start(ctx, Deps{}); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer s.Stop(ctx)
		if !strings.Contains(buf.String(), "WARNING") || !strings.Contains(buf.String(), "dev-mode") {
			t.Errorf("expected WARNING+dev-mode in log, got: %q", buf.String())
		}
	})
	t.Run("real key → silent", func(t *testing.T) {
		var buf strings.Builder
		realKey := make([]byte, 32)
		realKey[0] = 0x01 // any non-zero byte qualifies
		s := NewService(Config{
			CataloguePublisher: testCatPub,
			InstallRoot:        t.TempDir(),
			CatalogPubkey:      realKey,
			Logger:             log.New(&buf, "", 0),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Start(ctx, Deps{}); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer s.Stop(ctx)
		if strings.Contains(buf.String(), "WARNING") {
			t.Errorf("non-zero CatalogPubkey should not emit WARNING; got: %q", buf.String())
		}
	})
}

func TestNewServiceDefaults(t *testing.T) {
	s := NewService(Config{})
	if s.cfg.InstallRoot == "" {
		t.Errorf("default install root not set")
	}
	if s.cfg.CatalogPubkey == nil {
		t.Errorf("catalog pubkey nil — should default to embedded")
	}
	if s.Name() != "appstore" {
		t.Errorf("name: %q, want %q", s.Name(), "appstore")
	}
	if s.Order() <= 0 {
		t.Errorf("order: %d, want > 0", s.Order())
	}
}

func TestStartStopEmptyInstallRoot(t *testing.T) {
	dir := t.TempDir()
	s := NewService(Config{InstallRoot: dir, CataloguePublisher: testCatPub})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// No installed apps — supervisor finishes scanning immediately.
	if err := s.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestStartCreatesInstallRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "apps")
	s := NewService(Config{InstallRoot: dir, CataloguePublisher: testCatPub})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(ctx)

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("install root not created: %v", err)
	}
}

// TestRescanDiscoversAppInstalledMidRun spins up the supervisor with
// one app, then drops a second app's dir on disk and waits for the
// periodic rescan to pick it up. Without this loop, `pilotctl
// appstore install` requires a daemon restart to take effect — a
// real-ops paper cut and the missing link in the install flow.
func TestRescanDiscoversAppInstalledMidRun(t *testing.T) {
	root := t.TempDir()
	writeValidAppDir(t, root, "io.app1")

	svc := NewService(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     30 * time.Millisecond, // fast for tests
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := svc.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop(ctx)

	// Initial state: just app1.
	if got := len(svc.Apps()); got != 1 {
		t.Fatalf("initial Apps(): %d, want 1", got)
	}

	// Drop a second app dir while the supervisor is running.
	writeValidAppDir(t, root, "io.app2")

	// Wait for the rescan to find it. Poll instead of fixed sleep so
	// the test stays fast on a healthy box and resilient on a slow one.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := len(svc.Apps()); got == 2 {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("rescan never discovered io.app2 (Apps()=%v)", svc.Apps())
}

// TestRescanDetectsUninstall is the rescan loop's other half: after
// `pilotctl appstore uninstall` (modeled here by os.RemoveAll on the
// app dir), the supervisor must stop watching that app and drop it
// from Apps(). Without this, the supervise goroutine sits in
// verify-fail backoff forever until daemon restart.
func TestRescanDetectsUninstall(t *testing.T) {
	root := t.TempDir()
	app1Dir := writeValidAppDir(t, root, "io.app1")
	writeValidAppDir(t, root, "io.app2")

	svc := NewService(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     30 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := svc.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop(ctx)

	if got := len(svc.Apps()); got != 2 {
		t.Fatalf("initial Apps(): %d, want 2", got)
	}

	// Simulate uninstall. The supervise goroutine is actively
	// writing the supervisor.log file (via verify-fail audit lines),
	// so os.RemoveAll races against those writes — mirroring what
	// `pilotctl appstore uninstall` hits in production. Just removing
	// manifest.json suffices: that's the file rescanForGone checks.
	if err := os.Remove(filepath.Join(app1Dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		apps := svc.Apps()
		if len(apps) == 1 && apps[0].ID == "io.app2" {
			return // success — io.app1 dropped, io.app2 retained
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("rescan never detected uninstall of io.app1 (Apps()=%v)", svc.Apps())
}

// TestRescanResumeClearsSuspendedMarker confirms the round-trip:
// supervisor writes .suspended on crash-loop cap, rescanForResume
// (triggered by operator-dropped .resume) removes it. Without the
// removal, `pilotctl appstore list` would keep showing "SUSPENDED"
// after a successful restart — actively misleading.
func TestRescanResumeClearsSuspendedMarker(t *testing.T) {
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.suspended.app")

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.suspended.app"] = &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.suspended.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	sup.crashes["io.suspended.app"] = &crashRecord{suspended: true}
	sup.mu.Unlock()

	// Simulate the supervisor having written .suspended on entering
	// the suspend branch. (The real path in superviseOne writes it
	// just before returning; we synthesize the state here.)
	if err := os.WriteFile(filepath.Join(appDir, suspendedMarkerName), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Operator drops .resume.
	if err := os.WriteFile(filepath.Join(appDir, ".resume"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	resumed := sup.rescanForResume()
	if len(resumed) != 1 {
		t.Fatalf("rescanForResume returned %d, want 1", len(resumed))
	}

	// .suspended must be gone — otherwise list still reports SUSPENDED.
	if _, err := os.Stat(filepath.Join(appDir, suspendedMarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf(".suspended marker should be cleared after resume, stat err=%v", err)
	}
}

// TestRescanResumesAppOnMarker simulates the `pilotctl appstore restart`
// path: supervisor manages an app, the rescan tick picks up a .resume
// marker dropped into the app dir, clears the crash record, removes
// the marker, and relaunches a fresh supervise goroutine. Crash
// suspension and operator-resume together are the recovery story for
// an app that crashed-looped past its cap.
func TestRescanResumesAppOnMarker(t *testing.T) {
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.suspended.app")

	// Pre-populate a crash record (mimics what superviseOne does on
	// exceeding the crash-loop cap; we don't need the live goroutine
	// for the resume signal to be testable).
	sup := newSupervisor(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     20 * time.Millisecond,
	}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.suspended.app"] = &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.suspended.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	sup.crashes["io.suspended.app"] = &crashRecord{suspended: true}
	sup.mu.Unlock()

	// Drop the resume marker, then invoke the rescan directly so the
	// test doesn't depend on ticker timing.
	if err := os.WriteFile(filepath.Join(appDir, ".resume"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	resumed := sup.rescanForResume()
	if len(resumed) != 1 || resumed[0].Manifest.ID != "io.suspended.app" {
		t.Fatalf("rescanForResume: %+v, want [io.suspended.app]", resumed)
	}
	// Marker consumed.
	if _, err := os.Stat(filepath.Join(appDir, ".resume")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf(".resume marker should have been removed after consume, got err=%v", err)
	}
	// Crash record cleared.
	sup.mu.RLock()
	_, stillCrashed := sup.crashes["io.suspended.app"]
	sup.mu.RUnlock()
	if stillCrashed {
		t.Errorf("crashes record should have been cleared by rescanForResume")
	}
}

func TestScanIgnoresInvalidManifest(t *testing.T) {
	root := t.TempDir()
	// One app dir with a garbage manifest, one with no manifest.
	garbage := filepath.Join(root, "io.bad.app")
	_ = os.MkdirAll(garbage, 0o755)
	_ = os.WriteFile(filepath.Join(garbage, "manifest.json"), []byte("not json"), 0o644)

	empty := filepath.Join(root, "io.empty.app")
	_ = os.MkdirAll(empty, 0o755)

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("scan: got %d apps, want 0", len(apps))
	}
}
