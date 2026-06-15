package appstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestService_CallFrom_NotStarted covers the nil-supervisor guard.
func TestService_CallFrom_NotStarted(t *testing.T) {
	t.Parallel()
	err := (&Service{}).CallFrom(context.Background(), "io.caller", "io.target", "m", nil, nil)
	if err == nil {
		t.Fatal("expected 'service not started' error")
	}
}

// TestService_CallFrom_DelegatesToSupervisor drives the started-service
// path: an unknown target returns ErrAppNotInstalled, proving CallFrom
// delegates to the supervisor gate.
func TestService_CallFrom_DelegatesToSupervisor(t *testing.T) {
	t.Parallel()
	s := NewService(Config{InstallRoot: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Start(ctx, Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(ctx)

	if err := s.CallFrom(ctx, "io.caller", "io.unknown", "m", nil, nil); !errors.Is(err, ErrAppNotInstalled) {
		t.Fatalf("CallFrom unknown app: err = %v, want ErrAppNotInstalled", err)
	}
}
