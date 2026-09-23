package appstore

import (
	"bytes"
	"context"
	"os"
	"syscall"
	"time"
)

// reapGrace is how long a stale instance gets to exit on SIGTERM before
// it is SIGKILLed.
const reapGrace = 3 * time.Second

// Children run in their own process group (Setpgid), so when the daemon
// dies without running its shutdown path — the rx watchdog's os.Exit for
// supervisor respawn, SIGKILL, a crash — nothing signals them and they are
// reparented to init/launchd. Each respawn then started a fresh copy of
// every app next to the orphans: one laptop accumulated 94 copies of each
// of 12 apps (~2.8 GB RSS) in a week. Worse, when an orphan is finally
// terminated it unlinks the app socket it shares with the live instance,
// knocking the live app offline.
//
// reapStale runs before every spawn. It scans the process table for any
// instance of this app — a process whose argv carries both this app's
// binary path and its socket path — and terminates it. Matching on the
// full argv (not a pidfile) also cleans up orphans left behind by daemon
// versions that predate this check, and never touches a recycled pid.
// Returns the pids it reaped.
func (s *supervisor) reapStale(a *installedApp) []int {
	pids := findInstances(a.BinaryPath, a.SocketPath)
	for _, pid := range pids {
		s.logger.Printf("app=%s: reaping stale instance pid=%d left by a previous daemon", a.Manifest.ID, pid)
		// Negative pid → the whole process group the child leads; fall
		// back to the pid alone if it no longer leads a group.
		if syscall.Kill(-pid, syscall.SIGTERM) != nil {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	deadline := time.Now().Add(reapGrace)
	for _, pid := range pids {
		for time.Now().Before(deadline) && syscall.Kill(pid, 0) == nil {
			time.Sleep(50 * time.Millisecond)
		}
		if syscall.Kill(pid, 0) == nil {
			if syscall.Kill(-pid, syscall.SIGKILL) != nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	return pids
}

// findInstances returns the pids (other than this process) whose argv
// contains both binaryPath and socketPath as whole arguments.
func findInstances(binaryPath, socketPath string) []int {
	var out []int
	self := os.Getpid()
	for _, pid := range listPids() {
		if pid <= 1 || pid == self {
			continue
		}
		args, err := processArgs(pid)
		if err != nil {
			continue
		}
		if hasArg(args, binaryPath) && hasArg(args, socketPath) {
			out = append(out, pid)
		}
	}
	return out
}

// hasArg reports whether want appears as a whole NUL-delimited element of
// a raw argv buffer.
func hasArg(raw []byte, want string) bool {
	for _, arg := range bytes.Split(raw, []byte{0}) {
		if string(arg) == want {
			return true
		}
	}
	return false
}

// socketCheckInterval is how often a running app's socket is checked.
const socketCheckInterval = 5 * time.Second

// watchSocket terminates the app's process group if its socket vanishes
// while the process is still running, so the supervise loop respawns it
// and the app becomes reachable again. Without it the app lingers alive
// but unreachable ("stopped") until the next daemon restart — which is
// what happened when orphans sharing the socket path were terminated.
// Arms only once the socket has appeared, so slow starters are left alone.
func (s *supervisor) watchSocket(ctx context.Context, a *installedApp, pid int, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	seen := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, err := os.Stat(a.SocketPath)
		switch {
		case err == nil:
			seen = true
		case seen && os.IsNotExist(err):
			s.logger.Printf("app=%s: socket %s vanished while pid=%d is running — restarting it", a.Manifest.ID, a.SocketPath, pid)
			s.writeAuditLine(a, auditEvent{Event: "socket-lost", PID: pid})
			if syscall.Kill(-pid, syscall.SIGTERM) != nil {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
			return
		}
	}
}
