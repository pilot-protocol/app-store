//go:build !linux && !darwin

package appstore

import (
	"errors"
	"syscall"
)

// processArgs is unsupported here; reapStale then finds nothing.
func processArgs(pid int) ([]byte, error) {
	return nil, errors.New("process args not supported on this platform")
}

func listPids() []int { return nil }

func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

const lockSpawnThread = false
