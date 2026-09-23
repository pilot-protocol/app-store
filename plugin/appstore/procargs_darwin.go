//go:build darwin

package appstore

import "golang.org/x/sys/unix"

// processArgs returns the raw kern.procargs2 buffer for pid: argc, the
// exec path and the NUL-separated argv (followed by the environment).
func processArgs(pid int) ([]byte, error) {
	return unix.SysctlRaw("kern.procargs2", pid)
}
