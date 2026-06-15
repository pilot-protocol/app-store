package appstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// appWithBinary writes content to <dir>/<id>/bin and returns an
// installedApp whose manifest pins the sha256 of that content.
func appWithBinary(t *testing.T, root, id string, content []byte) *installedApp {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binPath, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	m := parseDummyManifest(t, id)
	m.Binary.SHA256 = hex.EncodeToString(sum[:])
	return &installedApp{
		Dir:        dir,
		BinaryPath: binPath,
		SocketPath: filepath.Join(dir, "app.sock"),
		Manifest:   m,
	}
}

// auditContains reports whether the app's supervisor.log contains needle.
func auditContains(t *testing.T, a *installedApp, needle string) bool {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(a.Dir, supervisorLogName))
	return strings.Contains(string(b), needle)
}

// TestSpawn_RefusesSymlinkSwap covers the TOCTOU case where the resolved
// binary is replaced by a symlink (e.g. → /bin/sh) after the scan but
// before exec: spawn must refuse and never launch.
func TestSpawn_RefusesSymlinkSwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := appWithBinary(t, root, "io.toctou.symlink", []byte("#!/bin/true\n"))
	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))

	// Swap the real binary for a symlink to a host binary.
	if err := os.Remove(a.BinaryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", a.BinaryPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if code := sup.spawn(ctx, a); code != -1 {
		t.Fatalf("spawn exit code = %d, want -1 (refused)", code)
	}
	if !auditContains(t, a, "spawn-time") || !auditContains(t, a, "symlink") {
		t.Errorf("expected spawn-time symlink verify-fail audit line; log missing it")
	}
}

// TestSpawn_RefusesContentSwap covers the TOCTOU case where the binary
// bytes change (sha256 no longer matches the pinned hash) between scan
// and exec.
func TestSpawn_RefusesContentSwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := appWithBinary(t, root, "io.toctou.content", []byte("original"))
	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))

	// Swap the bytes — pinned sha256 no longer matches.
	if err := os.WriteFile(a.BinaryPath, []byte("tampered-payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if code := sup.spawn(ctx, a); code != -1 {
		t.Fatalf("spawn exit code = %d, want -1 (refused)", code)
	}
	if !auditContains(t, a, "spawn-time") || !auditContains(t, a, "sha256 mismatch") {
		t.Errorf("expected spawn-time sha256 verify-fail audit line; log missing it")
	}
}

// TestVerifyAtSpawn_AcceptsGoodBinary confirms the guard passes for an
// untampered binary matching its pinned hash.
func TestVerifyAtSpawn_AcceptsGoodBinary(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := appWithBinary(t, root, "io.toctou.ok", []byte("good-bytes"))
	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))
	if err := sup.verifyAtSpawn(a); err != nil {
		t.Errorf("verifyAtSpawn rejected a valid binary: %v", err)
	}
}
