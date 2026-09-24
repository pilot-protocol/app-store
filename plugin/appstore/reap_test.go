//go:build linux || darwin

package appstore

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// fakeDaemonEnv switches the test binary into a "daemon" that supervises
// one app and blocks, so TestHardDaemonDeathLeavesNoOrphans can SIGKILL
// a real supervisor process.
const fakeDaemonEnv = "APPSTORE_TEST_FAKE_DAEMON_DIR"

// fakeOrphanEnv switches the test binary into a stand-in for an orphaned
// app (startFakeApp) that runs until its stdin closes or it is killed.
const fakeOrphanEnv = "APPSTORE_TEST_FAKE_ORPHAN"

func TestMain(m *testing.M) {
	if dir := os.Getenv(fakeDaemonEnv); dir != "" {
		runFakeDaemon(dir)
		return
	}
	if os.Getenv(fakeOrphanEnv) != "" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// longRunningApp writes an app "binary" that runs until killed and
// returns the installedApp describing it.
func longRunningApp(t *testing.T, dir string) *installedApp {
	t.Helper()
	body := "#!/bin/sh\nwhile :; do sleep 1; done\n"
	bin := filepath.Join(dir, "reap-app")
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeApp(dir, bin, sha256Hex([]byte(body)))
}

func fakeApp(dir, bin, sum string) *installedApp {
	m := &manifest.Manifest{ID: "io.test.reap"}
	m.Binary.SHA256 = sum
	return &installedApp{
		Manifest:   m,
		Dir:        dir,
		BinaryPath: bin,
		SocketPath: filepath.Join(dir, "app.sock"),
		DBPath:     filepath.Join(dir, "data.db"),
		IDPath:     filepath.Join(dir, "identity.json"),
	}
}

func runFakeDaemon(dir string) {
	bin := filepath.Join(dir, "reap-app")
	body, err := os.ReadFile(bin)
	if err != nil {
		os.Exit(2)
	}
	s := newSupervisor(Config{InstallRoot: dir}, Deps{}, log.New(io.Discard, "", 0))
	s.spawn(context.Background(), fakeApp(dir, bin, sha256Hex(body)))
	os.Exit(0)
}

func quietSupervisor() *supervisor {
	return newSupervisor(Config{}, Deps{}, log.New(io.Discard, "", 0))
}

// startFakeApp starts a long-lived process in its own process group whose
// argv carries the given strings, mimicking an orphaned app child. It is
// this test binary (fakeOrphanEnv), blocked reading a pipe the test holds
// open: its argv is final once Start returns and it never forks. A shell
// looping over `sleep` was neither — each forked child carries the
// shell's argv until its exec, and macOS's /bin/sh re-execs bash — so
// reapStale could see a third instance, or miss one mid-exec.
func startFakeApp(t *testing.T, argv ...string) *exec.Cmd {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^$"}, argv...)...)
	cmd.Env = append(os.Environ(), fakeOrphanEnv+"=1")
	cmd.Stdin = r
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = r.Close()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = w.Close()
	})
	return cmd
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

// waitFor polls cond until it holds or the timeout elapses.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

func TestReapStaleKillsEveryInstance(t *testing.T) {
	a := fakeApp(t.TempDir(), "/opt/pilot/apps/io.test.reap/bin/reap-app", "")
	// Two orphans from two earlier daemon lifetimes.
	first := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)
	second := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)

	// The test is the fakes' parent, so a terminated fake lingers as a
	// zombie until waitExited reaps it and reapStale runs out its grace
	// period; a real orphan belongs to init/launchd and is reaped at once.
	got := quietSupervisor().reapStale(a)
	if len(got) != 2 {
		t.Fatalf("reapStale = %v, want both pids %d and %d", got, first.Process.Pid, second.Process.Pid)
	}
	for _, cmd := range []*exec.Cmd{first, second} {
		if !waitExited(cmd, 5*time.Second) {
			t.Fatalf("stale instance pid=%d still running after reapStale", cmd.Process.Pid)
		}
	}
}

func TestReapStaleSparesOtherProcesses(t *testing.T) {
	a := fakeApp(t.TempDir(), "/opt/pilot/apps/io.test.reap/bin/reap-app", "")
	others := []*exec.Cmd{
		// Unrelated process.
		startFakeApp(t, "/usr/bin/unrelated", "--socket", "/tmp/other.sock"),
		// Same binary under another install root (different socket).
		startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath+".other"),
		// Paths only as substrings of longer arguments.
		startFakeApp(t, a.BinaryPath+"-v2", "--socket="+a.SocketPath),
	}
	if got := quietSupervisor().reapStale(a); len(got) != 0 {
		t.Fatalf("reapStale = %v, want none", got)
	}
	for _, cmd := range others {
		if waitExited(cmd, 200*time.Millisecond) {
			t.Fatalf("pid=%d (%v) was killed", cmd.Process.Pid, cmd.Args)
		}
	}
}

func TestWatchSocketRestartsAppWhenSocketVanishes(t *testing.T) {
	a := fakeApp(t.TempDir(), "/opt/pilot/apps/io.test.reap/bin/reap-app", "")
	cmd := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)
	if err := os.WriteFile(a.SocketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := quietSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.watchSocket(ctx, a, cmd.Process.Pid, 20*time.Millisecond)

	time.Sleep(100 * time.Millisecond) // let the watcher see the socket
	if err := os.Remove(a.SocketPath); err != nil {
		t.Fatal(err)
	}
	if !waitExited(cmd, 5*time.Second) {
		t.Fatal("app kept running after its socket vanished")
	}
}

func TestWatchSocketLeavesSlowStarterAlone(t *testing.T) {
	a := fakeApp(t.TempDir(), "/opt/pilot/apps/io.test.reap/bin/reap-app", "")
	cmd := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)
	s := quietSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.watchSocket(ctx, a, cmd.Process.Pid, 20*time.Millisecond)
	if waitExited(cmd, 300*time.Millisecond) {
		t.Fatal("app killed before its socket ever appeared")
	}
}

// TestHardDaemonDeathLeavesNoOrphans SIGKILLs a real supervisor process
// mid-flight — the rx watchdog's os.Exit and a crash look the same to its
// children — and checks that no app instance survives: on Linux the
// kernel kills it (Pdeathsig), elsewhere the next daemon reaps it before
// spawning a replacement.
func TestHardDaemonDeathLeavesNoOrphans(t *testing.T) {
	dir := t.TempDir()
	a := longRunningApp(t, dir)
	t.Cleanup(func() {
		for _, pid := range findInstances(a.BinaryPath, a.SocketPath) {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})

	daemon := exec.Command(os.Args[0], "-test.run=^$")
	daemon.Env = append(os.Environ(), fakeDaemonEnv+"="+dir)
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(10*time.Second, func() bool { return len(findInstances(a.BinaryPath, a.SocketPath)) == 1 }) {
		_ = daemon.Process.Kill()
		t.Fatal("fake daemon never spawned the app")
	}
	_ = daemon.Process.Kill()
	_ = daemon.Wait()

	if runtime.GOOS == "linux" {
		if !waitFor(5*time.Second, func() bool { return len(findInstances(a.BinaryPath, a.SocketPath)) == 0 }) {
			t.Fatal("app outlived the SIGKILLed daemon despite Pdeathsig")
		}
		return
	}
	orphans := findInstances(a.BinaryPath, a.SocketPath)
	if len(orphans) != 1 {
		t.Fatalf("expected the app to be orphaned, found %v", orphans)
	}
	// The respawned daemon reaps it before spawning a replacement.
	if got := quietSupervisor().reapStale(a); len(got) != 1 || got[0] != orphans[0] {
		t.Fatalf("reapStale = %v, want %v", got, orphans)
	}
	if !waitFor(5*time.Second, func() bool { return len(findInstances(a.BinaryPath, a.SocketPath)) == 0 }) {
		t.Fatal("orphan survived reapStale")
	}
}
