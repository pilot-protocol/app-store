package appstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// installTarget registers a ready target app exposing the given methods.
func installTarget(sup *supervisor, id string, exposes ...string) {
	sup.mu.Lock()
	sup.installed[id] = &installedApp{
		Dir:        "/nonexistent/" + id,
		SocketPath: "/nonexistent/" + id + "/app.sock",
		Manifest:   &manifest.Manifest{ID: id, Exposes: exposes},
	}
	sup.ready[id] = true
	sup.mu.Unlock()
}

// installCaller registers a caller app with the given ipc.call grants.
func installCaller(sup *supervisor, id string, grantTargets ...string) {
	var grants []manifest.Grant
	for _, gt := range grantTargets {
		grants = append(grants, manifest.Grant{Cap: "ipc.call", Target: gt})
	}
	sup.mu.Lock()
	sup.installed[id] = &installedApp{
		Dir:      "/nonexistent/" + id,
		Manifest: &manifest.Manifest{ID: id, Grants: grants},
	}
	sup.mu.Unlock()
}

// TestCallFrom_Gates exercises every authorization branch of callFrom
// without needing a live socket: each denial returns before the dial,
// and a fully-authorized call falls through to ErrAppNotReady only when
// the target socket is absent (here it dials a nonexistent path, so we
// assert the gate was passed by checking the error is NOT a gate error).
func TestCallFrom_Gates(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	t.Run("unknown target → ErrAppNotInstalled", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		err := sup.CallFrom(ctx, "io.caller", "io.missing", "ping", nil, nil)
		if !errors.Is(err, ErrAppNotInstalled) {
			t.Fatalf("err = %v, want ErrAppNotInstalled", err)
		}
	})

	t.Run("method not exposed → ErrMethodNotExposed", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		err := sup.CallFrom(ctx, "", "io.target", "io.target.secret", nil, nil)
		if !errors.Is(err, ErrMethodNotExposed) {
			t.Fatalf("err = %v, want ErrMethodNotExposed", err)
		}
	})

	t.Run("trusted caller skips grant gate", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		// Empty callerID = trusted; exposed method → passes gates, then
		// fails at dial (socket path is nonexistent). Must NOT be a gate err.
		err := sup.CallFrom(ctx, "", "io.target", "ping", nil, nil)
		if errors.Is(err, ErrGrantMissing) || errors.Is(err, ErrMethodNotExposed) || errors.Is(err, ErrAppNotInstalled) {
			t.Fatalf("trusted call should pass gates, got gate err: %v", err)
		}
	})

	t.Run("cross-app caller not installed → ErrGrantMissing", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		err := sup.CallFrom(ctx, "io.ghost", "io.target", "ping", nil, nil)
		if !errors.Is(err, ErrGrantMissing) {
			t.Fatalf("err = %v, want ErrGrantMissing", err)
		}
	})

	t.Run("cross-app caller without matching grant → ErrGrantMissing", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		installCaller(sup, "io.caller", "io.other.method") // wrong target
		err := sup.CallFrom(ctx, "io.caller", "io.target", "ping", nil, nil)
		if !errors.Is(err, ErrGrantMissing) {
			t.Fatalf("err = %v, want ErrGrantMissing", err)
		}
	})

	t.Run("cross-app caller with matching grant passes gates", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		installCaller(sup, "io.caller", "io.target.ping")
		err := sup.CallFrom(ctx, "io.caller", "io.target", "ping", nil, nil)
		if errors.Is(err, ErrGrantMissing) || errors.Is(err, ErrMethodNotExposed) {
			t.Fatalf("authorized call should pass gates, got: %v", err)
		}
	})

	t.Run("cross-app caller with wildcard grant passes gates", func(t *testing.T) {
		sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
		installTarget(sup, "io.target", "ping")
		installCaller(sup, "io.caller", "io.target.*")
		err := sup.CallFrom(ctx, "io.caller", "io.target", "ping", nil, nil)
		if errors.Is(err, ErrGrantMissing) {
			t.Fatalf("wildcard grant should authorize, got: %v", err)
		}
	})
}
