package appstore

import "testing"

// TestChildAddressSpaceLimitResolution covers the default-vs-override
// resolution of the RLIMIT_AS cap (platform-independent).
func TestChildAddressSpaceLimitResolution(t *testing.T) {
	t.Parallel()
	if got := newSupervisor(Config{}, Deps{}, newQuietLogger(t)).childAddressSpaceLimit(); got != defaultChildAddressSpaceLimit {
		t.Errorf("unset → %d, want default %d", got, defaultChildAddressSpaceLimit)
	}
	if got := newSupervisor(Config{ChildMemoryLimitBytes: 123 << 20}, Deps{}, newQuietLogger(t)).childAddressSpaceLimit(); got != 123<<20 {
		t.Errorf("override → %d, want %d", got, 123<<20)
	}
}
