//go:build linux

package appstore

import (
	"os/exec"
	"syscall"
	"testing"
	"unsafe"
)

// getChildRlimit reads back a resource limit for pid via prlimit64(2).
func getChildRlimit(t *testing.T, pid, resource int) rlimit64 {
	t.Helper()
	var out rlimit64
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRLIMIT64,
		uintptr(pid), uintptr(resource), 0,
		uintptr(unsafe.Pointer(&out)), 0, 0,
	)
	if errno != 0 {
		t.Fatalf("prlimit get pid=%d res=%d: %v", pid, resource, errno)
	}
	return out
}

func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// TestApplyChildResourceLimits_SetsAddressSpace asserts RLIMIT_AS and
// RLIMIT_NOFILE are actually applied to the child by reading them back.
func TestApplyChildResourceLimits_SetsAddressSpace(t *testing.T) {
	cmd := startSleeper(t)
	pid := cmd.Process.Pid
	const limit uint64 = 2 << 30
	applyChildResourceLimits(pid, limit, newQuietLogger(t))

	if got := getChildRlimit(t, pid, syscall.RLIMIT_AS); got.Cur != limit {
		t.Errorf("RLIMIT_AS Cur = %d, want %d", got.Cur, limit)
	}
	if got := getChildRlimit(t, pid, syscall.RLIMIT_NOFILE); got.Cur != childFDLimit {
		t.Errorf("RLIMIT_NOFILE Cur = %d, want %d", got.Cur, childFDLimit)
	}
}

// TestApplyChildResourceLimits_ZeroSkipsAddressSpace asserts a zero
// addrSpaceLimit leaves RLIMIT_AS untouched while still applying NOFILE.
func TestApplyChildResourceLimits_ZeroSkipsAddressSpace(t *testing.T) {
	cmd := startSleeper(t)
	pid := cmd.Process.Pid
	before := getChildRlimit(t, pid, syscall.RLIMIT_AS)
	applyChildResourceLimits(pid, 0, newQuietLogger(t))
	after := getChildRlimit(t, pid, syscall.RLIMIT_AS)
	if after.Cur != before.Cur {
		t.Errorf("RLIMIT_AS changed despite zero limit: before=%d after=%d", before.Cur, after.Cur)
	}
	if got := getChildRlimit(t, pid, syscall.RLIMIT_NOFILE); got.Cur != childFDLimit {
		t.Errorf("RLIMIT_NOFILE Cur = %d, want %d", got.Cur, childFDLimit)
	}
}
