//go:build linux

package appstore

import (
	"log"
	"syscall"
	"unsafe"
)

// childFDLimit caps an app's open-file-descriptor count via prlimit(2).
// Bounded at 256 — generous enough for any sensible app (sqlite, the
// app's listen socket, the daemon broker conn, a few peer sockets)
// but tight enough to refuse fork-bomb / fd-exhaustion abuse before
// the host hits a system-wide cap.
//
// Documented per-platform: this file applies under Linux only; the
// darwin / other variant is a no-op (see rlimit_other.go).
const childFDLimit uint64 = 256

// rlimit64 mirrors the kernel ABI for the prlimit64(2) syscall.
// We invoke the syscall directly to avoid pulling in golang.org/x/sys
// just for a single rlimit call — the supervisor module has no other
// need of x/sys, and the ABI here has been stable since Linux 2.6.36.
type rlimit64 struct {
	Cur uint64
	Max uint64
}

// applyChildResourceLimits sets resource limits on a freshly-spawned
// child after exec, via prlimit(2) targeting the child pid (so the
// supervisor's own limits are untouched). Best-effort: any failure logs
// but does not kill the spawn — the OS-wide ulimit still applies.
//
//   - RLIMIT_NOFILE is always set to childFDLimit.
//   - RLIMIT_AS (virtual address space) is set to addrSpaceLimit when it
//     is non-zero. NOTE: RLIMIT_AS bounds *address space*, not RSS.
//     Runtime-managed languages (Go, Node/V8, Python) reserve large
//     virtual regions well above their working set, so the cap must be
//     generous — a too-low value makes the runtime fail to mmap and the
//     child crashes on startup. The supervisor's default
//     (defaultChildAddressSpaceLimit) is chosen with that headroom.
//
// There is a tiny race: between cmd.Start and prlimit landing, the
// child can allocate. For an app starting from a clean state that's a
// handful of fds / a small allocation — well under the caps.
func applyChildResourceLimits(pid int, addrSpaceLimit uint64, logger *log.Logger) {
	setLimit := func(resource int, name string, val uint64) {
		want := rlimit64{Cur: val, Max: val}
		// SYS_PRLIMIT64 takes (pid, resource, *new_limit, *old_limit).
		// We don't care about the old limit; pass a nil out-pointer.
		_, _, errno := syscall.Syscall6(
			syscall.SYS_PRLIMIT64,
			uintptr(pid),
			uintptr(resource),
			uintptr(unsafe.Pointer(&want)),
			0, 0, 0,
		)
		if errno != 0 {
			logger.Printf("prlimit pid=%d %s=%d: %v (proceeding; OS-wide ulimit still applies)", pid, name, val, errno)
			return
		}
		logger.Printf("prlimit pid=%d %s=%d ok", pid, name, val)
	}

	setLimit(syscall.RLIMIT_NOFILE, "RLIMIT_NOFILE", childFDLimit)
	if addrSpaceLimit > 0 {
		setLimit(syscall.RLIMIT_AS, "RLIMIT_AS", addrSpaceLimit)
	}
}
