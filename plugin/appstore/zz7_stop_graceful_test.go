//go:build linux || darwin

package appstore

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// gracefulApp writes an app stand-in that creates the socket the
// supervisor passes with --socket, starts a subprocess, and then idles.
// With ignoreTerm=false it traps SIGTERM like a real app's shutdown path:
// it records the signal, removes its socket and exits 0. With
// ignoreTerm=true it (and the subprocess, which inherits the ignored
// disposition) ignores SIGTERM, to exercise the SIGKILL fallback.
func gracefulApp(t *testing.T, ignoreTerm bool) (a *installedApp, termMarker, childPID string) {
	t.Helper()
	dir := t.TempDir()
	termMarker = filepath.Join(dir, "got-sigterm")
	childPID = filepath.Join(dir, "child.pid")
	trap := `trap 'echo term > "` + termMarker + `"; rm -f "$SOCK"; exit 0' TERM`
	if ignoreTerm {
		trap = `trap '' TERM`
	}
	body := "#!/bin/sh\n" +
		"while [ $# -gt 0 ]; do [ \"$1\" = --socket ] && SOCK=$2; shift; done\n" +
		trap + "\n" +
		": > \"$SOCK\"\n" +
		"sleep 300 &\n" +
		"echo $! > " + childPID + "\n" +
		"while :; do sleep 0.05; done\n"
	bin := filepath.Join(dir, "graceful-app")
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeApp(dir, bin, sha256Hex([]byte(body))), termMarker, childPID
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	var pid int
	if !waitFor(10*time.Second, func() bool {
		raw, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		return pid > 0
	}) {
		t.Fatalf("%s never written", path)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

// TestStopLetsAppShutDown: stopping an app (daemon shutdown, uninstall, a
// replacing rescan) delivers SIGTERM first, so the app runs its own
// shutdown and removes its socket, and the stop reports the app's real
// exit status. A straight SIGKILL skipped all of that: the wallet never
// closed its ledger and left app.sock behind.
func TestStopLetsAppShutDown(t *testing.T) {
	a, termMarker, childPIDFile := gracefulApp(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan int, 1)
	go func() { exited <- quietSupervisor().spawn(ctx, a) }()

	child := readPID(t, childPIDFile)
	if !waitFor(10*time.Second, func() bool { _, err := os.Stat(a.SocketPath); return err == nil }) {
		t.Fatal("app never created its socket")
	}

	start := time.Now()
	cancel()
	var code int
	select {
	case code = <-exited:
	case <-time.After(appStopGrace + 10*time.Second):
		t.Fatal("spawn did not return after the app was stopped")
	}
	if took := time.Since(start); took >= appStopGrace {
		t.Errorf("stop took %s; an app that exits on SIGTERM should not wait out the %s grace", took, appStopGrace)
	}
	if b, err := os.ReadFile(termMarker); err != nil || !strings.Contains(string(b), "term") {
		t.Errorf("app never received SIGTERM (marker %q, err %v)", b, err)
	}
	if _, err := os.Stat(a.SocketPath); !os.IsNotExist(err) {
		t.Errorf("socket %s left behind after a graceful stop (stat err=%v)", a.SocketPath, err)
	}
	if code != 0 {
		t.Errorf("spawn returned %d, want the app's own exit status 0", code)
	}
	if !waitFor(5*time.Second, func() bool { return processGone(child) }) {
		t.Errorf("subprocess pid=%d outlived the app it belongs to", child)
	}
}

// TestStopKillsAppThatIgnoresSIGTERM: an app (and its subprocess) that
// ignore SIGTERM are SIGKILLed as a group once appStopGrace runs out.
func TestStopKillsAppThatIgnoresSIGTERM(t *testing.T) {
	a, _, childPIDFile := gracefulApp(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan int, 1)
	go func() { exited <- quietSupervisor().spawn(ctx, a) }()

	child := readPID(t, childPIDFile)

	start := time.Now()
	cancel()
	select {
	case <-exited:
	case <-time.After(appStopGrace + 10*time.Second):
		t.Fatal("an app that ignores SIGTERM was never killed")
	}
	if took := time.Since(start); took < appStopGrace-100*time.Millisecond {
		t.Errorf("returned after %s; expected the %s grace before SIGKILL", took, appStopGrace)
	}
	if !waitFor(5*time.Second, func() bool { return processGone(child) }) {
		t.Fatalf("subprocess pid=%d (ignoring SIGTERM) survived the group SIGKILL", child)
	}
}

// TestStopAppGroupAlreadyExited: cancelling after the app has exited on
// its own is not an error exec treats as a failed cancel.
func TestStopAppGroupAlreadyExited(t *testing.T) {
	p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "exit 0"}, &os.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := stopAppGroup(p, time.Second); err != nil && err != os.ErrProcessDone {
		t.Fatalf("stopAppGroup on an exited process: %v", err)
	}
}
