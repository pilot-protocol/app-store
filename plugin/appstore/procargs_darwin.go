//go:build darwin

package appstore

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// processArgs returns the raw kern.procargs2 buffer for pid: argc, the
// exec path and the NUL-separated argv (followed by the environment).
func processArgs(pid int) ([]byte, error) {
	return unix.SysctlRaw("kern.procargs2", pid)
}

// listPids returns every pid in the process table.
func listPids() []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(procs))
	for _, p := range procs {
		pids = append(pids, int(p.Proc.P_pid))
	}
	return pids
}

// childSysProcAttr puts each app in its own process group. macOS has no
// parent-death signal; orphans are cleaned up by reapStale when the
// respawned daemon next spawns the app.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

const lockSpawnThread = false
