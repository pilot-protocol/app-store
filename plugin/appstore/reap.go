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

// killAppGroup SIGKILLs the process group a running app leads: the app and
// any process it started that did not move itself to a group of its own
// (setsid/setpgid). It is the app's exec.Cmd.Cancel, so it runs before
// Wait has reaped the app: the app's pid, which is also the group id, is
// still held (by the app, or its zombie) and cannot have been reused. When
// the group cannot be signalled it falls back to the app alone, which is
// what exec's default Cancel does.
func killAppGroup(p *os.Process) error {
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return p.Kill()
}

// appStopGrace is how long a stopped app gets to run its own shutdown
// after SIGTERM before its process group is SIGKILLed. It fits inside the
// daemon's 5s plugin stop budget (pilotprotocol cmd/daemon
// pluginStopTimeout); apps are stopped in parallel.
const appStopGrace = 3 * time.Second

// stopPollInterval is how often stopAppGroup checks whether the app has
// exited during its grace period.
const stopPollInterval = 20 * time.Millisecond

// stopAppGroup is the app's exec.Cmd.Cancel. It asks the process group
// the app leads to terminate (SIGTERM), so the app runs its shutdown path:
// finish in-flight calls, close its database, remove its socket. If the
// app is still running after grace, the whole group is SIGKILLed
// (killAppGroup), so nothing the app started outlives it.
//
// It returns once the app has exited. Exec's Wait reaps the app
// concurrently; once it has, Signal reports os.ErrProcessDone. Until then
// the app's pid, which is also the group id, is held by the app or its
// zombie, so the group signals cannot reach a recycled pid.
func stopAppGroup(p *os.Process, grace time.Duration) error {
	// exec can call Cancel after Wait has already reaped the app (ctx
	// cancelled just as it exited). Then there is nothing to stop, and its
	// pid must not be signalled as a group.
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return err
	}
	if syscall.Kill(-p.Pid, syscall.SIGTERM) != nil {
		// Not a group leader (or already gone): the app alone.
		if err := p.Signal(syscall.SIGTERM); err != nil {
			return err // os.ErrProcessDone: it already exited
		}
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if p.Signal(syscall.Signal(0)) != nil {
			return nil // exited and reaped
		}
		time.Sleep(stopPollInterval)
	}
	return killAppGroup(p)
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
		if ctx.Err() != nil {
			// Being stopped: the app removing its socket on SIGTERM is
			// its normal shutdown, not a lost socket.
			return
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
