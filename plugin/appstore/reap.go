package appstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// appPidFileName records the pid of the app process the supervisor last
// spawned. Children run in their own process group (Setpgid), so when the
// daemon dies without running its shutdown path — the rx watchdog's
// os.Exit for supervisor respawn, SIGKILL, a crash — nothing signals them
// and they are reparented to init/launchd. Each respawn then starts a
// fresh copy of every app next to the orphans. In the field this left 94
// copies of each of 12 apps (~2.8 GB RSS) on one laptop after a week of
// watchdog restarts. The next spawn reads this file and reaps the orphan.
const appPidFileName = "app.pid"

// reapGrace is how long a stale child gets to exit on SIGTERM before it
// is SIGKILLed.
const reapGrace = 3 * time.Second

// reapStale terminates a still-running instance recorded in the app's
// pidfile. The pid is only signalled if its command line still names this
// app's binary and socket, so a recycled pid belonging to an unrelated
// process is never touched. Returns the reaped pid, or 0.
func (s *supervisor) reapStale(a *installedApp) int {
	pidPath := filepath.Join(a.Dir, appPidFileName)
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return 0
	}
	defer os.Remove(pidPath)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return 0
	}
	args, err := processArgs(pid)
	if err != nil || !bytes.Contains(args, []byte(a.BinaryPath)) || !bytes.Contains(args, []byte(a.SocketPath)) {
		return 0
	}
	s.logger.Printf("app=%s: reaping orphaned instance pid=%d left by a previous daemon", a.Manifest.ID, pid)
	// Negative pid → the whole process group the child leads.
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(reapGrace)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return pid
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return pid
}

// writePidFile records a freshly-started child's pid for reapStale.
func (s *supervisor) writePidFile(a *installedApp, pid int) {
	if err := os.WriteFile(filepath.Join(a.Dir, appPidFileName), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		s.logger.Printf("app=%s: write pidfile: %v", a.Manifest.ID, err)
	}
}

// removePidFile clears the pidfile once the child has been waited on.
func removePidFile(a *installedApp) {
	_ = os.Remove(filepath.Join(a.Dir, appPidFileName))
}
