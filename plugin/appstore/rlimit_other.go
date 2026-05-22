//go:build !linux

package appstore

import "log"

// applyChildResourceLimits is the non-Linux build's no-op. macOS's
// equivalent (setrlimit) affects the calling process, not children;
// without a wrapper binary or pre-exec hook there's no portable way
// to bound the child's fd count from the supervisor. Documented as
// an RC1 known gap; production deployments on linux get the real
// limit via rlimit_linux.go's applyChildResourceLimits.
func applyChildResourceLimits(pid int, logger *log.Logger) {
	// Single startup log line would be nicer than per-spawn, but
	// inlining here keeps the supervisor call-site identical to
	// the Linux build. Cheap log line at info level — easy to grep.
	logger.Printf("resource limits not enforced for pid=%d on this platform (linux-only)", pid)
}
