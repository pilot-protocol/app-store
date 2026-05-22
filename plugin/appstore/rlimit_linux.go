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

// applyChildResourceLimits sets RLIMIT_NOFILE on a freshly-spawned
// child after exec. Best-effort: a failure logs but doesn't kill the
// spawn — the OS-wide ulimit still applies. We use prlimit (not
// setrlimit) because the parent (supervisor) doesn't want to bound
// its own fd count; we only want to bound the child's.
//
// There is a tiny race: between cmd.Start and prlimit landing, the
// child can open more fds. For a wallet-class app starting from a
// clean state, that's a handful at most — well under the cap.
func applyChildResourceLimits(pid int, logger *log.Logger) {
	want := rlimit64{Cur: childFDLimit, Max: childFDLimit}
	// SYS_PRLIMIT64 takes (pid, resource, *new_limit, *old_limit).
	// We don't care about the old limit; pass a nil out-pointer.
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRLIMIT64,
		uintptr(pid),
		uintptr(syscall.RLIMIT_NOFILE),
		uintptr(unsafe.Pointer(&want)),
		0, 0, 0,
	)
	if errno != 0 {
		logger.Printf("prlimit pid=%d RLIMIT_NOFILE=%d: %v (proceeding; OS-wide ulimit still applies)", pid, childFDLimit, errno)
		return
	}
	logger.Printf("prlimit pid=%d RLIMIT_NOFILE=%d ok", pid, childFDLimit)
}
