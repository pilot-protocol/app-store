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

// TestStopKillsAppSubprocesses: stopping an app (the ctx cancel that daemon
// shutdown, uninstall and a replacing rescan all use) also stops the
// processes the app started. exec's default cancel killed only the app's
// own pid, so they were reparented to launchd/init and ran on.
func TestStopKillsAppSubprocesses(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	body := "#!/bin/sh\nsleep 300 &\necho $! > " + pidFile + "\nwhile :; do sleep 1; done\n"
	bin := filepath.Join(dir, "group-app")
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	a := fakeApp(dir, bin, sha256Hex([]byte(body)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan int, 1)
	go func() { exited <- quietSupervisor().spawn(ctx, a) }()

	var child int
	if !waitFor(10*time.Second, func() bool {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		child, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		return child > 0
	}) {
		t.Fatal("app never started its subprocess")
	}
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })

	cancel()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("spawn did not return after the app was stopped")
	}
	if !waitFor(5*time.Second, func() bool { return processGone(child) }) {
		t.Fatalf("subprocess pid=%d outlived the app it belongs to", child)
	}
}

// processGone reports whether pid has exited. Killed and reparented, it
// stays a zombie until pid 1 reaps it, which a container's pid 1 (often
// the test binary's parent) may never do, so on Linux a zombie counts as
// gone.
func processGone(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return true
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// pid (comm) state ...: comm may contain spaces, so read after the last ')'.
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && s[i+2] == 'Z'
}
