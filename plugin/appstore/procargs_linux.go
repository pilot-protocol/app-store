//go:build linux

package appstore

import (
	"os"
	"strconv"
	"syscall"
)

// processArgs returns the NUL-separated argv of pid.
func processArgs(pid int) ([]byte, error) {
	return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
}

// listPids returns every pid in /proc.
func listPids() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// childSysProcAttr puts each app in its own process group and has the
// kernel SIGKILL it if the daemon dies, however it dies. Pdeathsig fires
// when the *thread* that forked the child exits, so spawn keeps that
// thread locked for the child's lifetime (see lockSpawnThread).
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// lockSpawnThread reports whether spawn must pin its OS thread from Start
// to Wait for childSysProcAttr's Pdeathsig to be tied to the daemon's
// lifetime rather than to an arbitrary runtime thread.
const lockSpawnThread = true
