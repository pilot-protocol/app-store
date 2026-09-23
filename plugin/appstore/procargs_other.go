//go:build !linux && !darwin

package appstore

import "errors"

// processArgs is unsupported here; reapStale then leaves the pid alone.
func processArgs(pid int) ([]byte, error) {
	return nil, errors.New("process args not supported on this platform")
}
