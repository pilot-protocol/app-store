//go:build linux || darwin

package appstore

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// startFakeApp starts a long-lived process in its own process group whose
// argv carries the given strings, mimicking an orphaned app child.
func startFakeApp(t *testing.T, argv ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", "sleep 30"}, argv...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); _ = cmd.Wait() })
	return cmd
}

func reapFixture(t *testing.T) (*supervisor, *installedApp) {
	t.Helper()
	dir := t.TempDir()
	a := &installedApp{
		Manifest:   &manifest.Manifest{ID: "io.test.reap"},
		Dir:        dir,
		BinaryPath: filepath.Join(dir, "bin", "reap-app"),
		SocketPath: filepath.Join(dir, "app.sock"),
	}
	return &supervisor{logger: log.New(io.Discard, "", 0)}, a
}

// waitExited reaps cmd and reports whether it exited within the timeout.
func waitExited(cmd *exec.Cmd, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestReapStaleKillsOrphanedInstance(t *testing.T) {
	s, a := reapFixture(t)
	cmd := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)
	s.writePidFile(a, cmd.Process.Pid)

	// The test is the fake's parent, so the terminated child lingers as a
	// zombie until waitExited reaps it and reapStale runs out its grace
	// period; a real orphan belongs to init/launchd and is reaped at once.
	if got := s.reapStale(a); got != cmd.Process.Pid {
		t.Fatalf("reapStale = %d, want %d", got, cmd.Process.Pid)
	}
	if !waitExited(cmd, 5*time.Second) {
		t.Fatal("orphaned instance still running after reapStale")
	}
	if _, err := os.Stat(filepath.Join(a.Dir, appPidFileName)); !os.IsNotExist(err) {
		t.Fatalf("pidfile not removed: %v", err)
	}
}

func TestReapStaleSparesUnrelatedProcess(t *testing.T) {
	s, a := reapFixture(t)
	// A recycled pid: same number, but not this app's binary/socket.
	cmd := startFakeApp(t, "/usr/bin/unrelated", "--socket", "/tmp/other.sock")
	if err := os.WriteFile(filepath.Join(a.Dir, appPidFileName), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := s.reapStale(a); got != 0 {
		t.Fatalf("reapStale = %d, want 0 for an unrelated process", got)
	}
	if waitExited(cmd, 300*time.Millisecond) {
		t.Fatal("unrelated process was killed")
	}
}

func TestReapStaleNoPidFile(t *testing.T) {
	s, a := reapFixture(t)
	if got := s.reapStale(a); got != 0 {
		t.Fatalf("reapStale = %d, want 0", got)
	}
}
