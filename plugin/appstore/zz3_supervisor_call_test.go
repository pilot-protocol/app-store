package appstore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// startAppSocket runs an ipc.Serve loop on a unix socket at the supplied
// path, dispatching the named method to handler. Returns a cleanup
// func that closes the listener.
func startAppSocket(t *testing.T, socketPath, method string, handler ipc.Handler) func() {
	t.Helper()
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	d := ipc.NewDispatcher()
	d.Register(method, handler)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = ipc.Serve(context.Background(), c, d)
			}(conn)
		}
	}()
	return func() {
		_ = l.Close()
		wg.Wait()
	}
}

// shortSocketPath returns a unix-socket path short enough to fit in
// sockaddr_un (macOS: ~104 bytes). t.TempDir paths on macOS often
// exceed that, so we create the socket directly under /tmp.
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "as-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// TestSupervisor_Call_HappyPath wires a real listening app.sock and
// drives the full Service.Call → supervisor.Call → ipc.Call path,
// hitting the dialer-deadline + successful IPC branches.
func TestSupervisor_Call_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.call.happy")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := shortSocketPath(t, "app.sock")
	cleanup := startAppSocket(t, socketPath, "echo",
		func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
			return req.Payload, nil
		})
	defer cleanup()

	mh := parseDummyManifest(t, "io.call.happy")
	mh.Exposes = []string{"echo"}
	sup := newSupervisor(Config{InstallRoot: dir, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.call.happy"] = &installedApp{
		Dir:        appDir,
		SocketPath: socketPath,
		Manifest:   mh,
	}
	sup.ready["io.call.happy"] = true
	sup.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out string
	if err := sup.Call(ctx, "io.call.happy", "echo", "ping", &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out != "ping" {
		t.Errorf("out = %q, want %q", out, "ping")
	}
}

// TestSupervisor_Call_PropagatesServerError exercises the EnvErr path
// — the app returns an error and Call surfaces it.
func TestSupervisor_Call_PropagatesServerError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.call.err")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := shortSocketPath(t, "app.sock")
	cleanup := startAppSocket(t, socketPath, "boom",
		func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
			return nil, errors.New("app rejected")
		})
	defer cleanup()

	me := parseDummyManifest(t, "io.call.err")
	me.Exposes = []string{"boom"}
	sup := newSupervisor(Config{InstallRoot: dir, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.call.err"] = &installedApp{
		Dir:        appDir,
		SocketPath: socketPath,
		Manifest:   me,
	}
	sup.ready["io.call.err"] = true
	sup.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := sup.Call(ctx, "io.call.err", "boom", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "app rejected") {
		t.Errorf("err = %v, want 'app rejected'", err)
	}
}

// TestRescanForResume_IntegrationViaRunLoop drops a .resume marker into
// an installed app's dir, lets the supervisor's run loop pick it up,
// and confirms rescanForResume's return value lands a fresh supervise
// goroutine (audit log shows supervise-start after the marker drop).
func TestRescanForResume_IntegrationViaRunLoop(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	appDir := writeValidAppDir(t, root, "io.resume.run")

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

	// Wait until the initial supervise-start landed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if body, _ := os.ReadFile(filepath.Join(appDir, supervisorLogName)); strings.Contains(string(body), "supervise-start") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Drop the resume marker and let the rescan tick re-invoke
	// rescanForResume; the integration completes when a "resume" audit
	// line appears in the log.
	if err := os.WriteFile(filepath.Join(appDir, ".resume"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		body, _ := os.ReadFile(filepath.Join(appDir, supervisorLogName))
		if strings.Contains(string(body), `"resume"`) {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, _ := os.ReadFile(filepath.Join(appDir, supervisorLogName))
	t.Errorf("rescanForResume did not emit a resume audit line within 2s; log=%s", body)
}

// TestRotateAuditIfLarge_NoActiveLogIsNoOp covers the "first write or
// perm issue" branch where os.Stat returns an error.
func TestRotateAuditIfLarge_NoActiveLogIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir, AuditLogMaxBytes: 1, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	// Should not panic or create anything.
	sup.rotateAuditIfLarge(dir)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("rotateAuditIfLarge with no active log created files: %v", entries)
	}
}

// TestWriteAuditLine_OpenFailure simulates an unwritable app dir so
// the os.OpenFile inside writeAuditLine fails — covers the audit-open
// error branch. Audit is best-effort: this must NOT panic and must not
// corrupt the supervisor.
func TestWriteAuditLine_OpenFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create the app dir read-only so we can't open supervisor.log for
	// writing. (root will bypass the perm; skip if running as root.)
	if os.Geteuid() == 0 {
		t.Skip("running as root; file mode perms ignored")
	}
	appDir := filepath.Join(dir, "io.audit.locked")
	if err := os.Mkdir(appDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(appDir, 0o700) //nolint:errcheck // best-effort teardown
	app := &installedApp{Dir: appDir, Manifest: parseDummyManifest(t, "io.audit.locked")}
	sup := newSupervisor(Config{InstallRoot: dir, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	// Must not panic — the supervisor logs the open error and returns.
	sup.writeAuditLine(app, auditEvent{Event: "spawn", PID: 1})
}

// TestSuperviseOne_VerifyFailRetriesPastBackoff drives a verify-fail
// loop and cancels after the second iteration, hitting the "select
// case <-time.After(maxBackoff)" branch.
func TestSuperviseOne_VerifyFailRetriesPastBackoff(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.supervise.retry")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(appDir, "bin")
	if err := os.WriteFile(path, []byte("wrong-hash"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &installedApp{
		Dir:        appDir,
		BinaryPath: path,
		SocketPath: filepath.Join(appDir, "app.sock"),
		DBPath:     filepath.Join(appDir, "data.db"),
		IDPath:     filepath.Join(appDir, "identity.json"),
		Manifest:   parseDummyManifest(t, "io.supervise.retry"),
	}
	sup := newSupervisor(Config{InstallRoot: dir, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		sup.superviseOne(ctx, a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatal("superviseOne stuck in verify-fail loop")
	}
}
