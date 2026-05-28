package appstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompareVersions exercises the semver comparison helper.
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.1.0", 1},
		{"1.1.0", "1.2.0", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"0.0.1", "0.0.0", 1},
		{"9.99.9", "10.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},  // prerelease < release
		{"1.0.0", "1.0.0-alpha", 1},    // release > prerelease
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.a, tt.b), func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestRegisterRefusesDowngrade confirms that registerInstalled skips
// a manifest whose app_version is lower than an already-registered
// entry for the same app ID.
func TestRegisterRefusesDowngrade(t *testing.T) {
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.test.app")

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))

	// Register the current (newer) version first.
	current := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	current.Manifest.AppVersion = "2.0.0"
	sup.registerInstalled([]*installedApp{current})
	if _, ok := sup.installed["io.test.app"]; !ok {
		t.Fatal("io.test.app not registered")
	}
	if sup.installed["io.test.app"].Manifest.AppVersion != "2.0.0" {
		t.Fatalf("expected 2.0.0, got %s", sup.installed["io.test.app"].Manifest.AppVersion)
	}

	// Now try to register a downgrade: v1.0.0.
	downgrade := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	downgrade.Manifest.AppVersion = "1.0.0"
	sup.registerInstalled([]*installedApp{downgrade})

	// The in-memory entry must still be 2.0.0.
	if got := sup.installed["io.test.app"].Manifest.AppVersion; got != "2.0.0" {
		t.Errorf("downgrade was accepted — version now %s, want 2.0.0", got)
	}
}

// TestRegisterAllowsUpgrade confirms registerInstalled accepts a
// same-app-id entry with a higher app_version.
func TestRegisterAllowsUpgrade(t *testing.T) {
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.test.app")

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))

	old := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	old.Manifest.AppVersion = "1.0.0"
	sup.registerInstalled([]*installedApp{old})

	upgrade := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	upgrade.Manifest.AppVersion = "3.0.0"
	sup.registerInstalled([]*installedApp{upgrade})

	if got := sup.installed["io.test.app"].Manifest.AppVersion; got != "3.0.0" {
		t.Errorf("upgrade not accepted — version now %s, want 3.0.0", got)
	}
}

// TestRegisterSameVersionIsIdempotent confirms registering the same
// version twice is a no-op.
func TestRegisterSameVersionIsIdempotent(t *testing.T) {
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.test.app")

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))

	a1 := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	a1.Manifest.AppVersion = "1.5.0"
	a2 := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	a2.Manifest.AppVersion = "1.5.0"

	sup.registerInstalled([]*installedApp{a1})
	sup.registerInstalled([]*installedApp{a2})
	if sup.installed["io.test.app"].Manifest.AppVersion != "1.5.0" {
		t.Errorf("expected 1.5.0, got %s", sup.installed["io.test.app"].Manifest.AppVersion)
	}
}

// writeAppDirWithVersion creates a valid app dir with a manifest
// carrying the given version, and a stub binary.
func writeAppDirWithVersion(t *testing.T, root, id, version string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "x"), []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(
		`{"id":%q,"app_version":%q,"manifest_version":1,"binary":{"runtime":"go","path":"bin/x","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"grants":[{"cap":"net.dial","target":"*"}],"store":{"publisher":"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"sig"}}`,
		id, version,
	)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRescanRefusesDowngradeMidRun verifies that when an on-disk
// manifest is replaced with a lower app_version while the daemon
// is running, the rescan loop refuses to accept it.
func TestRescanRefusesDowngradeMidRun(t *testing.T) {
	root := t.TempDir()
	appDir := writeAppDirWithVersion(t, root, "io.test.app", "2.0.0")

	sup := newSupervisor(Config{
		InstallRoot:    root,
		RescanInterval: 20 * 1e6, // not used directly in this test
	}, Deps{}, newQuietLogger(t))

	// Register the app in-memory as if already discovered at startup.
	entry := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	entry.Manifest.AppVersion = "2.0.0"
	sup.mu.Lock()
	sup.installed["io.test.app"] = entry
	sup.mu.Unlock()

	// Replace on-disk manifest with a downgrade (v1.0.0).
	writeAppDirWithVersion(t, root, "io.test.app", "1.0.0")
	fresh := sup.rescanForNew()
	if len(fresh) != 0 {
		t.Errorf("rescanForNew returned %d apps, want 0 (downgrade should be refused)", len(fresh))
	}
	sup.mu.RLock()
	v := sup.installed["io.test.app"].Manifest.AppVersion
	sup.mu.RUnlock()
	if v != "2.0.0" {
		t.Errorf("version was downgraded: got %s, want 2.0.0", v)
	}
}

// TestRescanAllowsUpgradeMidRun verifies that when an on-disk
// manifest is replaced with a higher app_version while the daemon
// is running, the rescan loop detects and accepts it.
func TestRescanAllowsUpgradeMidRun(t *testing.T) {
	root := t.TempDir()
	appDir := writeAppDirWithVersion(t, root, "io.test.app", "1.0.0")

	sup := newSupervisor(Config{
		InstallRoot:    root,
		RescanInterval: 20 * 1e6,
	}, Deps{}, newQuietLogger(t))

	entry := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	entry.Manifest.AppVersion = "1.0.0"
	sup.mu.Lock()
	sup.installed["io.test.app"] = entry
	sup.mu.Unlock()

	// Replace on-disk manifest with upgrade (v2.0.0).
	writeAppDirWithVersion(t, root, "io.test.app", "2.0.0")
	fresh := sup.rescanForNew()
	if len(fresh) != 1 {
		t.Fatalf("rescanForNew returned %d, want 1 (upgrade should be accepted)", len(fresh))
	}
	sup.mu.RLock()
	v := sup.installed["io.test.app"].Manifest.AppVersion
	sup.mu.RUnlock()
	if v != "2.0.0" {
		t.Errorf("upgrade not applied: got %s, want 2.0.0", v)
	}
}

// TestRescanAuditLogsDowngradeRefusal confirms the supervisor writes an
// audit event when refusing a downgrade during rescan.
func TestRescanAuditLogsDowngradeRefusal(t *testing.T) {
	root := t.TempDir()
	appDir := writeAppDirWithVersion(t, root, "io.test.app", "2.0.0")

	sup := newSupervisor(Config{
		InstallRoot:    root,
		RescanInterval: 20 * 1e6,
	}, Deps{}, newQuietLogger(t))

	entry := &installedApp{
		Dir:        appDir,
		Manifest:   parseDummyManifest(t, "io.test.app"),
		BinaryPath: filepath.Join(appDir, "bin/x"),
	}
	entry.Manifest.AppVersion = "2.0.0"
	sup.mu.Lock()
	sup.installed["io.test.app"] = entry
	sup.mu.Unlock()

	// Replace on-disk with downgrade.
	writeAppDirWithVersion(t, root, "io.test.app", "1.0.0")
	fresh := sup.rescanForNew()
	if len(fresh) != 0 {
		t.Errorf("downgrade should have been refused")
	}

	// Check the audit log for downgrade-refused event.
	auditPath := filepath.Join(appDir, supervisorLogName)
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "downgrade-refused") {
		t.Errorf("audit log missing downgrade-refused event:\n%s", string(data))
	}
}
