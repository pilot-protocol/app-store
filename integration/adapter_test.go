package integration

import (
	"context"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/app-store/plugin/appstore"
)

// TestAdapterImplementsCoreapi is partly redundant with the compile-time
// `var _ coreapi.Service = (*Adapter)(nil)` in adapter.go — but it
// surfaces the assertion as a named test for any CI / coverage report
// that lists test names.
func TestAdapterImplementsCoreapi(t *testing.T) {
	var _ coreapi.Service = (*Adapter)(nil)
}

// TestAdapterStartStopRoundtrip drives the Adapter the way the daemon's
// runtime will: New → Start with a real-shaped coreapi.Deps populated
// with no-op stubs, then Stop. Asserts no error from either step and
// that Name / Order forward correctly.
func TestAdapterStartStopRoundtrip(t *testing.T) {
	dir := t.TempDir()
	svc := appstore.NewService(appstore.Config{InstallRoot: dir})
	adapter := New(svc)

	if adapter.Name() != "appstore" {
		t.Errorf("Name: %q, want %q", adapter.Name(), "appstore")
	}
	if adapter.Order() != 120 {
		t.Errorf("Order: %d, want 120", adapter.Order())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// All optional fields nil — the shim treats them as `any` and never
	// touches them in the empty-install-root path.
	deps := coreapi.Deps{}
	if err := adapter.Start(ctx, deps); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := adapter.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}
