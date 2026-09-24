//go:build !linux

package appstore

import (
	"log"
	"sync"
)

var resourceLimitWarning sync.Once

// applyChildResourceLimits is the non-Linux build's no-op. macOS's
// equivalent (setrlimit) affects the calling process, not children;
// without a wrapper binary or pre-exec hook there's no portable way to
// bound the child's fd count or address space from the supervisor.
// Documented as an RC1 known gap; production deployments on linux get
// the real limits (RLIMIT_NOFILE + RLIMIT_AS) via rlimit_linux.go.
//
// The addrSpaceLimit parameter is accepted for signature parity with the
// Linux build and ignored here.
func applyChildResourceLimits(pid int, addrSpaceLimit uint64, logger *log.Logger) {
	resourceLimitWarning.Do(func() {
		logger.Print("resource limits not enforced on this platform (linux-only); child file-descriptor and address-space caps are ignored")
	})
}
