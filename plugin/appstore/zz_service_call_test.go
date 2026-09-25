package appstore

import (
	"context"
	"errors"
	"fmt"
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

// fakeIdentityAddr has an Address() string method.
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

// fakeIdentityNoAddr has no Address method at all.
type fakeIdentityNoAddr struct{}

func (fakeIdentityNoAddr) NodeID() uint32 { return 1 }

func TestDaemonAddrFromDeps_IdentityWithoutAddressFallsBack(t *testing.T) {
	t.Parallel()
	got := daemonAddrFromDeps(Deps{Identity: fakeIdentityNoAddr{}})
	if got != "0:0001.0000.0000" {
		t.Errorf("got %q, want sentinel", got)
	}
}

// fakeProtoAddr mirrors common/protocol.Addr: a struct whose String() renders
// the address. coreapi.Identity.Address() returns this, not a string.
type fakeProtoAddr struct {
	Network uint16
	Node    uint32
}

func (a fakeProtoAddr) String() string {
	return fmt.Sprintf("%d:%04X.%04X.%04X", a.Network, a.Network, (a.Node>>16)&0xFFFF, a.Node&0xFFFF)
}

// fakeCoreIdentity has coreapi.Identity's real Address signature.
type fakeCoreIdentity struct{ addr fakeProtoAddr }

func (f fakeCoreIdentity) Address() fakeProtoAddr { return f.addr }
func (f fakeCoreIdentity) NodeID() uint32         { return f.addr.Node }

// The real daemon hands the supervisor a coreapi.Identity; its address must
// reach the app, not the sentinel. Before the fix every wallet on every node
// was started with --addr 0:0001.0000.0000.
func TestDaemonAddrFromDeps_CoreapiIdentityAddress(t *testing.T) {
	t.Parallel()
	got := daemonAddrFromDeps(Deps{Identity: fakeCoreIdentity{addr: fakeProtoAddr{Node: 0x3D971}}})
	if got != "0:0000.0003.D971" {
		t.Errorf("got %q, want 0:0000.0003.D971", got)
	}
}

// Address methods that take arguments or return something unprintable are
// not addresses; they fall back to the sentinel rather than panicking.
type fakeIdentityOddAddr struct{}

func (fakeIdentityOddAddr) Address(int) string { return "x" }

func TestDaemonAddrFromDeps_UnusableAddressMethodFallsBack(t *testing.T) {
	t.Parallel()
	if got := daemonAddrFromDeps(Deps{Identity: fakeIdentityOddAddr{}}); got != "0:0001.0000.0000" {
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
