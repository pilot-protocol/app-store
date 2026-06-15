package appstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSupervisor_Apps_EmptyOnFresh(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	if got := sup.Apps(); len(got) != 0 {
		t.Errorf("Apps on fresh sup = %v", got)
	}
}

func TestSupervisor_Get_UnknownReturnsNil(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	if got := sup.Get("not-installed"); got != nil {
		t.Errorf("Get(unknown) = %v, want nil", got)
	}
}

func TestSupervisor_Get_AfterRegister(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	app := &installedApp{
		Dir:      dir,
		Manifest: parseDummyManifest(t, "io.test.app"),
	}
	sup.mu.Lock()
	sup.installed["io.test.app"] = app
	sup.mu.Unlock()

	if got := sup.Get("io.test.app"); got == nil {
		t.Error("Get after register = nil")
	}
	if got := sup.Apps(); len(got) != 1 {
		t.Errorf("Apps len = %d, want 1", len(got))
	}
}

func TestSupervisor_Call_NotInstalled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	err := sup.Call(context.Background(), "io.no.such", "method", nil, nil)
	if !errors.Is(err, ErrAppNotInstalled) {
		t.Errorf("err = %v, want ErrAppNotInstalled", err)
	}
}

func TestSupervisor_Call_NotReady(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	m := parseDummyManifest(t, "io.test.app")
	m.Exposes = []string{"method"} // method must be exposed to reach the ready gate
	sup.mu.Lock()
	sup.installed["io.test.app"] = &installedApp{
		Dir:      dir,
		Manifest: m,
	}
	sup.mu.Unlock()

	// Use a context that's about to cancel so awaitReady's poll returns false fast.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sup.Call(ctx, "io.test.app", "method", nil, nil)
	if !errors.Is(err, ErrAppNotReady) {
		t.Errorf("err = %v, want ErrAppNotReady", err)
	}
}

func TestSupervisor_MarkReadyAndNotReady(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.markReady("io.x")
	sup.mu.RLock()
	if !sup.ready["io.x"] {
		t.Error("after markReady: ready[io.x] = false")
	}
	sup.mu.RUnlock()

	sup.markNotReady("io.x")
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if _, ok := sup.ready["io.x"]; ok {
		t.Error("after markNotReady: still in ready map")
	}
}

func TestSupervisor_AwaitReady_AlreadyReady(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.markReady("io.fast")
	if !sup.awaitReady(context.Background(), "io.fast", time.Second) {
		t.Error("awaitReady on ready app: want true")
	}
}

func TestApps_SuspendedFlagFromCrashRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.mu.Lock()
	sup.installed["io.crash"] = &installedApp{
		Dir:      dir,
		Manifest: parseDummyManifest(t, "io.crash"),
	}
	sup.crashes["io.crash"] = &crashRecord{suspended: true}
	sup.mu.Unlock()

	got := sup.Apps()
	if len(got) != 1 {
		t.Fatalf("Apps len = %d", len(got))
	}
	if !got[0].Suspended {
		t.Error("Suspended flag should be true")
	}
}

func TestDaemonAddrFromDeps_NilDepsReturnsSentinel(t *testing.T) {
	t.Parallel()
	// With no Identity wired the function falls back to a non-routable
	// sentinel — just verify it returns SOMETHING (covers the fallback).
	got := daemonAddrFromDeps(Deps{})
	if got == "" {
		t.Error("expected non-empty sentinel fallback")
	}
}
