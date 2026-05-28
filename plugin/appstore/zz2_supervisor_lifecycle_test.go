package appstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBinaryScript builds a shell-script "binary" under tmpDir that
// exits with the configured code after the requested sleep duration.
// Returns the resolved path AND the sha256 hex digest of the written
// file so the manifest can pin it correctly for verifyBinary.
//
// This is the os/exec mock surface the supervisor lifecycle tests use:
// instead of mocking exec.Command (Go does not allow that), we hand
// the supervisor a real on-disk executable whose behavior we control.
func fakeBinaryScript(t *testing.T, dir, name string, exitCode int, sleep time.Duration) (path, sum string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary scripts use POSIX shell; not portable to Windows")
	}
	path = filepath.Join(dir, name)
	body := fmt.Sprintf("#!/bin/sh\nsleep %.2f\nexit %d\n", sleep.Seconds(), exitCode)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	h := sha256.Sum256([]byte(body))
	return path, hex.EncodeToString(h[:])
}

// TestVerifyBinary_OK confirms a matching sha256 passes verifyBinary.
func TestVerifyBinary_OK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, sum := fakeBinaryScript(t, dir, "x", 0, 0)
	a := &installedApp{
		BinaryPath: path,
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.verify.ok"),
	}
	a.Manifest.Binary.SHA256 = sum
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	if err := sup.verifyBinary(a); err != nil {
		t.Errorf("verifyBinary: %v", err)
	}
}

// TestVerifyBinary_Mismatch covers the sha256-mismatch return path.
func TestVerifyBinary_Mismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, _ := fakeBinaryScript(t, dir, "x", 0, 0)
	a := &installedApp{
		BinaryPath: path,
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.verify.mismatch"),
	}
	// Manifest sha256 is the placeholder all-zeros from parseDummyManifest;
	// the actual file hash will differ.
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	err := sup.verifyBinary(a)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("err = %v, want sha256 mismatch", err)
	}
}

// TestVerifyBinary_MissingFile covers the open-error path.
func TestVerifyBinary_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := &installedApp{
		BinaryPath: filepath.Join(dir, "does-not-exist"),
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.verify.missing"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	err := sup.verifyBinary(a)
	if err == nil || !strings.Contains(err.Error(), "open binary") {
		t.Errorf("err = %v, want open binary error", err)
	}
}

// TestSpawn_FastExitTriggersExitCode runs a real spawn against a fake
// binary that exits cleanly with code 0. Drives the cmd.Start →
// applyChildResourceLimits → cmd.Wait happy path.
func TestSpawn_FastExitTriggersExitCode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.spawn.fast")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, _ := fakeBinaryScript(t, appDir, "bin", 0, 0)

	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.spawn.fast"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	code := sup.spawn(ctx, a)
	if code != 0 {
		t.Errorf("spawn exit code = %d, want 0", code)
	}
}

// TestSpawn_NonZeroExitPropagates runs against a fake binary that
// exits with code 42 and confirms spawn surfaces that as the return
// value. Drives the *exec.ExitError branch of cmd.Wait.
func TestSpawn_NonZeroExitPropagates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.spawn.exit42")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, _ := fakeBinaryScript(t, appDir, "bin", 42, 0)

	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.spawn.exit42"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	code := sup.spawn(ctx, a)
	if code != 42 {
		t.Errorf("spawn exit code = %d, want 42", code)
	}
}

// TestSpawn_StartFailure exercises the "missing binary" branch where
// exec.Start fails outright. Should return -1 and emit a spawn-fail
// audit line.
func TestSpawn_StartFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.spawn.nostart")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := &installedApp{
		Dir:        appDir,
		BinaryPath: filepath.Join(appDir, "does-not-exist"),
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.spawn.nostart"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	code := sup.spawn(ctx, a)
	if code != -1 {
		t.Errorf("spawn exit code = %d, want -1 on Start failure", code)
	}
	// spawn-fail audit line should have landed.
	logBody, err := os.ReadFile(filepath.Join(appDir, supervisorLogName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(logBody), `"spawn-fail"`) {
		t.Errorf("expected spawn-fail event in audit log, got: %s", logBody)
	}
}

// TestSpawn_StaleSocketIsCleaned drives the "drop stale socket" branch
// at the top of spawn.
func TestSpawn_StaleSocketIsCleaned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.spawn.stale")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(appDir, "app.sock")
	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, _ := fakeBinaryScript(t, appDir, "bin", 0, 0)

	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: socketPath,
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.spawn.stale"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = sup.spawn(ctx, a)
	// After spawn returns the fake binary has exited; the supervisor
	// removed the stale socket at the start. waitReady might or might
	// not have observed it before the binary exited — the assertion is
	// that the supervisor's pre-spawn rm step ran (i.e. the file no
	// longer matches its original "stale" contents).
	if body, err := os.ReadFile(socketPath); err == nil && string(body) == "stale" {
		t.Errorf("stale socket was not cleaned before spawn")
	}
}

// TestWaitReady_SocketAppears drives waitReady with a real socket file
// that's created mid-wait; confirms ready flips to true.
func TestWaitReady_SocketAppears(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "app.sock")
	a := &installedApp{
		SocketPath: socketPath,
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.waitready.ok"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sup.waitReady(context.Background(), a, 2*time.Second)
	}()

	// Create the socket after a short delay.
	time.Sleep(75 * time.Millisecond)
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if !sup.ready["io.waitready.ok"] {
		t.Errorf("waitReady did not flip ready after socket creation")
	}
}

// TestWaitReady_Timeout covers the "socket never appears" branch.
func TestWaitReady_Timeout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := &installedApp{
		SocketPath: filepath.Join(dir, "never.sock"),
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.waitready.timeout"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.waitReady(context.Background(), a, 50*time.Millisecond)
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if sup.ready["io.waitready.timeout"] {
		t.Errorf("ready should be false on timeout")
	}
}

// TestWaitReady_CtxCanceled covers the ctx.Err() branch of waitReady.
func TestWaitReady_CtxCanceled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := &installedApp{
		SocketPath: filepath.Join(dir, "never.sock"),
		Dir:        dir,
		Manifest:   parseDummyManifest(t, "io.waitready.cancel"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sup.waitReady(ctx, a, time.Second)
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if sup.ready["io.waitready.cancel"] {
		t.Errorf("ready should not be set when ctx is canceled")
	}
}

// TestAwaitReady_Timeout covers the polling-timeout branch.
func TestAwaitReady_Timeout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	if got := sup.awaitReady(context.Background(), "io.never", 50*time.Millisecond); got {
		t.Errorf("awaitReady = true, want false on timeout")
	}
}

// TestAwaitReady_FlipsToReadyMidPoll exercises the success branch
// where ready flips true during the poll.
func TestAwaitReady_FlipsToReadyMidPoll(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	go func() {
		time.Sleep(50 * time.Millisecond)
		sup.markReady("io.delayed")
	}()
	if !sup.awaitReady(context.Background(), "io.delayed", 2*time.Second) {
		t.Errorf("awaitReady should return true after flip")
	}
}

// TestSuperviseOne_VerifyFailLoops drives superviseOne against an app
// whose binary doesn't match its pinned sha256, then cancels ctx
// shortly after to confirm the verify-fail backoff path returns.
func TestSuperviseOne_VerifyFailLoops(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.supervise.verifyfail")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Real file but wrong sha256 in the dummy manifest.
	path := filepath.Join(appDir, "bin")
	if err := os.WriteFile(path, []byte("real but wrong-hash"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.supervise.verifyfail"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sup.superviseOne(ctx, a)
		close(done)
	}()
	// Wait long enough for at least one verify-fail audit line to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if body, err := os.ReadFile(filepath.Join(appDir, supervisorLogName)); err == nil &&
			strings.Contains(string(body), `"verify-fail"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(35 * time.Second):
		t.Fatal("superviseOne did not return after ctx cancel (verify-fail backoff stuck)")
	}
	body, _ := os.ReadFile(filepath.Join(appDir, supervisorLogName))
	if !strings.Contains(string(body), `"verify-fail"`) {
		t.Errorf("expected verify-fail line in audit log, got: %s", body)
	}
}

// TestSuperviseOne_SpawnSuspendThenExits drives the crash-loop path:
// run with a binary that exits immediately, force the suspend branch
// to fire by lowering the cap via injected crash records, then confirm
// the suspended marker lands.
func TestSuperviseOne_CrashLoopSuspends(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.supervise.crashloop")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, sum := fakeBinaryScript(t, appDir, "bin", 1, 0)
	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.supervise.crashloop"),
	}
	a.Manifest.Binary.SHA256 = sum
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	// Pre-fill crash record so the very first exit trips the cap.
	now := time.Now()
	sup.crashes["io.supervise.crashloop"] = &crashRecord{
		times: []time.Time{now, now, now, now, now, now},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		sup.superviseOne(ctx, a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("superviseOne did not return after crash-loop cap")
	}
	// Suspended marker should now exist.
	if _, err := os.Stat(filepath.Join(appDir, suspendedMarkerName)); err != nil {
		t.Errorf(".suspended marker missing after crash-loop cap: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(appDir, supervisorLogName))
	if !strings.Contains(string(body), `"suspend"`) {
		t.Errorf("expected suspend event in audit log, got: %s", body)
	}
}

// TestResolveUnder_EmptyPath covers the empty-path error branch.
func TestResolveUnder_EmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := resolveUnder("/tmp", ""); err == nil {
		t.Error("expected error for empty rel path")
	}
}

// TestResolveUnder_AbsolutePath covers the absolute-path error branch.
func TestResolveUnder_AbsolutePath(t *testing.T) {
	t.Parallel()
	if _, err := resolveUnder("/tmp", "/etc/passwd"); err == nil {
		t.Error("expected error for absolute rel path")
	}
}

// TestResolveUnder_Escape covers the path-escapes-base branch.
func TestResolveUnder_Escape(t *testing.T) {
	t.Parallel()
	if _, err := resolveUnder("/tmp/app", "../../etc/passwd"); err == nil {
		t.Error("expected error for path escaping base")
	}
}

// TestResolveUnder_OK confirms the happy path returns a path under base.
func TestResolveUnder_OK(t *testing.T) {
	t.Parallel()
	got, err := resolveUnder("/tmp/app", "bin/wallet")
	if err != nil {
		t.Fatalf("resolveUnder: %v", err)
	}
	if !strings.HasSuffix(got, "/bin/wallet") {
		t.Errorf("got %q, want path ending in /bin/wallet", got)
	}
}

// TestScanInstalled_MissingRoot covers the os.IsNotExist branch.
func TestScanInstalled_MissingRoot(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Errorf("err = %v, want nil for missing root", err)
	}
	if len(apps) != 0 {
		t.Errorf("apps = %v, want empty", apps)
	}
}

// TestScanInstalled_SkipsNonDirs confirms file entries in the root
// don't crash the scan.
func TestScanInstalled_SkipsNonDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stray-file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("apps = %v, want empty (stray file should be ignored)", apps)
	}
}

// TestScanInstalled_RejectsTraversalPath drops a manifest whose
// binary.path tries to escape via "..", confirms scanInstalled drops it.
func TestScanInstalled_RejectsTraversalPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.evil.app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{
		"id": "io.evil.app",
		"manifest_version": 1,
		"app_version": "0.0.0",
		"protection": "shareable",
		"binary": {"runtime": "go", "path": "../../../bin/sh", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"exposes": ["io.evil.app.method"],
		"grants": [{"cap": "fs.read", "target": "$APP/data.db"}],
		"store": {"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "signature": "sig:p"}
	}`
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("apps = %v, want empty (traversal must be rejected)", apps)
	}
}

// TestScanInstalled_RejectsSymlinkBinary drops a manifest whose binary
// path resolves to a symlink, confirms scanInstalled rejects it.
func TestScanInstalled_RejectsSymlinkBinary(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks unreliable on Windows test runners")
	}
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.symlink.app")
	if err := os.MkdirAll(filepath.Join(appDir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Drop a symlink at appDir/bin/x → /bin/sh
	link := filepath.Join(appDir, "bin", "x")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	body := `{
		"id": "io.symlink.app",
		"manifest_version": 1,
		"app_version": "0.0.0",
		"protection": "shareable",
		"binary": {"runtime": "go", "path": "bin/x", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"exposes": ["io.symlink.app.method"],
		"grants": [{"cap": "fs.read", "target": "$APP/data.db"}],
		"store": {"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "signature": "sig:p"}
	}`
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("apps = %v, want empty (symlink binary must be rejected)", apps)
	}
}

// TestApplyChildResourceLimits_NonLinuxOrInvalidPID exercises the
// stub on non-linux platforms; on linux, calling against an invalid
// PID logs but does not panic.
func TestApplyChildResourceLimits_Smoke(t *testing.T) {
	t.Parallel()
	// Pass an invalid PID; the function is best-effort and must not panic.
	logger := newQuietLogger(t)
	applyChildResourceLimits(0, logger)
}

// TestService_AppsBeforeStart returns nil per the docstring.
func TestService_AppsBeforeStart(t *testing.T) {
	t.Parallel()
	s := &Service{}
	if got := s.Apps(); got != nil {
		t.Errorf("Apps before Start = %v, want nil", got)
	}
}

// TestService_DoubleStartReturnsError covers the "already started"
// guard in Service.Start.
func TestService_DoubleStartReturnsError(t *testing.T) {
	t.Parallel()
	s := NewService(Config{InstallRoot: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Start(ctx, Deps{}); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer s.Stop(ctx)
	if err := s.Start(ctx, Deps{}); err == nil {
		t.Error("double Start: expected 'already started' error")
	}
}

// TestService_StopIdempotent covers the early-return branch when sup
// is nil.
func TestService_StopIdempotent(t *testing.T) {
	t.Parallel()
	s := NewService(Config{InstallRoot: t.TempDir()})
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop on never-started service: %v", err)
	}
}

// TestService_StartFailsWhenInstallRootIsAFile drives the MkdirAll
// failure branch (passing a path that's an existing regular file).
func TestService_StartFailsWhenInstallRootIsAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "as-file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewService(Config{InstallRoot: path})
	err := s.Start(context.Background(), Deps{})
	if err == nil {
		t.Error("expected Start to fail when InstallRoot is a file")
	}
}

// TestCatalogPubkeyIsPlaceholder_NonZero confirms a key with any
// non-zero byte is not flagged as the placeholder.
func TestCatalogPubkeyIsPlaceholder_NonZero(t *testing.T) {
	t.Parallel()
	pk := make([]byte, 32)
	pk[5] = 0xAA
	if catalogPubkeyIsPlaceholder(pk) {
		t.Error("non-zero key flagged as placeholder")
	}
}

// TestCatalogPubkeyIsPlaceholder_EmptyAndNil exercises the empty / nil
// branch.
func TestCatalogPubkeyIsPlaceholder_EmptyAndNil(t *testing.T) {
	t.Parallel()
	if !catalogPubkeyIsPlaceholder(nil) {
		t.Error("nil should be placeholder")
	}
	if !catalogPubkeyIsPlaceholder([]byte{}) {
		t.Error("empty should be placeholder")
	}
}

// TestService_Call_UnknownAppReturnsErrAppNotInstalled drives the full
// Service.Call → sup.Call path for the unknown-app branch.
func TestService_Call_UnknownAppReturnsErrAppNotInstalled(t *testing.T) {
	t.Parallel()
	s := NewService(Config{InstallRoot: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(ctx)
	err := s.Call(ctx, "io.unknown", "method", nil, nil)
	if !errors.Is(err, ErrAppNotInstalled) {
		t.Errorf("err = %v, want ErrAppNotInstalled", err)
	}
}

// TestSupervisor_Call_DialFailsWhenNoServer wires up an installed app
// with a ready bit set but no socket → dial fails fast.
func TestSupervisor_Call_DialFailsWhenNoServer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.dial.fail")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.dial.fail"] = &installedApp{
		Dir:        appDir,
		SocketPath: filepath.Join(appDir, "missing.sock"),
		Manifest:   parseDummyManifest(t, "io.dial.fail"),
	}
	sup.ready["io.dial.fail"] = true
	sup.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := sup.Call(ctx, "io.dial.fail", "any", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dial") {
		t.Errorf("err = %v, want dial error", err)
	}
}

// TestSupervisor_Get_NilSafe covers nil-receiver smoke on Get.
func TestSupervisor_Get_OK(t *testing.T) {
	t.Parallel()
	sup := newSupervisor(Config{InstallRoot: t.TempDir()}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["x"] = &installedApp{Manifest: parseDummyManifest(t, "x")}
	sup.mu.Unlock()
	if got := sup.Get("x"); got == nil {
		t.Error("Get returned nil for installed app")
	}
}
