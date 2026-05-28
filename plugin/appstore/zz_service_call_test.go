package appstore

import (
	"context"
	"errors"
	"testing"
)

func TestService_Call_NotStarted(t *testing.T) {
	t.Parallel()
	s := &Service{}
	err := s.Call(context.Background(), "io.test", "method", nil, nil)
	if err == nil {
		t.Error("expected 'service not started' error")
	}
}

// fakeIdentityAddr satisfies the identityAddresser interface in supervisor.go.
type fakeIdentityAddr struct{ addr string }

func (f *fakeIdentityAddr) Address() string { return f.addr }
func (f *fakeIdentityAddr) NodeID() uint32  { return 7 }

func TestDaemonAddrFromDeps_NonEmptyAddressReturned(t *testing.T) {
	t.Parallel()
	got := daemonAddrFromDeps(Deps{Identity: &fakeIdentityAddr{addr: "1:0001.0002.0003"}})
	if got != "1:0001.0002.0003" {
		t.Errorf("got %q", got)
	}
}

func TestDaemonAddrFromDeps_EmptyAddressFallsBackToSentinel(t *testing.T) {
	t.Parallel()
	got := daemonAddrFromDeps(Deps{Identity: &fakeIdentityAddr{addr: ""}})
	if got != "0:0001.0000.0000" {
		t.Errorf("got %q, want sentinel", got)
	}
}

// fakeIdentityNoAddr satisfies coreapi.Identity but NOT the identityAddresser
// interface (no Address method) — exercises the type-assertion miss branch.
type fakeIdentityNoAddr struct{}

func (fakeIdentityNoAddr) NodeID() uint32 { return 1 }

func TestDaemonAddrFromDeps_IdentityWithoutAddressFallsBack(t *testing.T) {
	t.Parallel()
	got := daemonAddrFromDeps(Deps{Identity: fakeIdentityNoAddr{}})
	if got != "0:0001.0000.0000" {
		t.Errorf("got %q, want sentinel", got)
	}
}

// TestSupervisor_Call_NilArgsAndOut covers the args/out nil-passthrough path.
func TestSupervisor_Call_NilArgsAndOut(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	err := sup.Call(context.Background(), "io.not.installed", "method", nil, nil)
	if !errors.Is(err, ErrAppNotInstalled) {
		t.Errorf("want ErrAppNotInstalled, got %v", err)
	}
}
