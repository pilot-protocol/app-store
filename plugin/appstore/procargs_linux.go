//go:build linux

package appstore

import (
	"os"
	"strconv"
)

// processArgs returns the NUL-separated argv of pid.
func processArgs(pid int) ([]byte, error) {
	return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
}
