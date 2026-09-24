//go:build !linux

package appstore

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

func TestResourceLimitWarningOnce(t *testing.T) {
	resourceLimitWarning = sync.Once{}
	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(pid int) { defer wg.Done(); applyChildResourceLimits(pid, 4<<30, logger) }(i)
	}
	wg.Wait()
	if got := strings.Count(output.String(), "resource limits not enforced"); got != 1 {
		t.Fatalf("warnings=%d: %s", got, output.String())
	}
}
