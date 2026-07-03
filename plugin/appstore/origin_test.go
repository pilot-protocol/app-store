package appstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// originCapture is a handler that records the Origin block of every
// request it serves. Safe for the concurrent Serve goroutines that
// startAppSocket spins up.
type originCapture struct {
	mu   sync.Mutex
	seen []*ipc.Origin
}

func (c *originCapture) handler(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
	c.mu.Lock()
	c.seen = append(c.seen, req.Origin)
	c.mu.Unlock()
	return json.RawMessage(`"ok"`), nil
}

func (c *originCapture) last(t *testing.T) *ipc.Origin {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		t.Fatal("handler never ran")
	}
	return c.seen[len(c.seen)-1]
}

// installLiveApp registers id as installed+ready against a real listening
// app.sock whose method dispatches into capture.
func installLiveApp(t *testing.T, sup *supervisor, id, method string, capture *originCapture) {
	t.Helper()
	dir := t.TempDir()
	appDir := filepath.Join(dir, id)
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := shortSocketPath(t, "app.sock")
	cleanup := startAppSocket(t, socketPath, method, capture.handler)
	t.Cleanup(cleanup)

	m := parseDummyManifest(t, id)
	m.Exposes = []string{method}
	sup.mu.Lock()
	sup.installed[id] = &installedApp{Dir: appDir, SocketPath: socketPath, Manifest: m}
	sup.ready[id] = true
	sup.mu.Unlock()
}

// TestCallWithOrigin_DeliversOrigin drives the trusted bridge path end to
// end: supervisor.CallWithOrigin must stamp the daemon-attested origin on
// the request envelope the app's handler sees.
func TestCallWithOrigin_DeliversOrigin(t *testing.T) {
	t.Parallel()
	sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
	capture := &originCapture{}
	installLiveApp(t, sup, "io.origin.target", "whoami", capture)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	origin := &ipc.Origin{Node: "1:0001.ABCD.1234", NodeID: 42, Authenticated: true, Trusted: true}
	var out string
	if err := sup.CallWithOrigin(ctx, "io.origin.target", "whoami", nil, &out, origin); err != nil {
		t.Fatalf("CallWithOrigin: %v", err)
	}
	got := capture.last(t)
	if got == nil {
		t.Fatal("handler saw nil origin, want attested block")
	}
	if *got != *origin {
		t.Errorf("origin = %+v, want %+v", *got, *origin)
	}
}

// TestCallWithOrigin_GatesStillApply confirms the trusted-origin path is
// not a gate bypass: the broker-surface (exposes) check runs before any
// socket is dialed.
func TestCallWithOrigin_GatesStillApply(t *testing.T) {
	t.Parallel()
	sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
	capture := &originCapture{}
	installLiveApp(t, sup, "io.origin.gated", "whoami", capture)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	origin := &ipc.Origin{Node: "1:0001.0000.0001", NodeID: 1, Authenticated: true}
	err := sup.CallWithOrigin(ctx, "io.origin.gated", "secret", nil, nil, origin)
	if !errors.Is(err, ErrMethodNotExposed) {
		t.Fatalf("err = %v, want ErrMethodNotExposed", err)
	}
	err = sup.CallWithOrigin(ctx, "io.missing", "whoami", nil, nil, origin)
	if !errors.Is(err, ErrAppNotInstalled) {
		t.Fatalf("err = %v, want ErrAppNotInstalled", err)
	}
}

// TestCallFrom_StripsOrigin is the anti-forgery seam: even if an origin
// reaches callFrom alongside a non-empty callerID (a cross-app call), the
// target app must see Origin == nil. Apps cannot launder a forged origin
// through the broker.
func TestCallFrom_StripsOrigin(t *testing.T) {
	t.Parallel()
	sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
	capture := &originCapture{}
	installLiveApp(t, sup, "io.origin.victim", "whoami", capture)
	installCaller(sup, "io.origin.attacker", "io.origin.victim.whoami")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	forged := &ipc.Origin{Node: "1:0001.DEAD.BEEF", NodeID: 99, Authenticated: true, Trusted: true}
	var out string
	if err := sup.callFrom(ctx, "io.origin.attacker", "io.origin.victim", "whoami", nil, &out, forged); err != nil {
		t.Fatalf("callFrom: %v", err)
	}
	if got := capture.last(t); got != nil {
		t.Errorf("cross-app call delivered origin %+v, want nil", *got)
	}
}

// TestCallAndCallFrom_NoOriginByDefault confirms the plain Call path
// keeps delivering origin-less envelopes.
func TestCallAndCallFrom_NoOriginByDefault(t *testing.T) {
	t.Parallel()
	sup := newSupervisor(Config{}, Deps{}, newQuietLogger(t))
	capture := &originCapture{}
	installLiveApp(t, sup, "io.origin.plain", "whoami", capture)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out string
	if err := sup.Call(ctx, "io.origin.plain", "whoami", nil, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := capture.last(t); got != nil {
		t.Errorf("Call delivered origin %+v, want nil", *got)
	}
}

// TestService_CallWithOrigin_NotStarted mirrors the existing
// not-started guard tests for the new public entry point.
func TestService_CallWithOrigin_NotStarted(t *testing.T) {
	t.Parallel()
	s := &Service{}
	err := s.CallWithOrigin(context.Background(), "io.test", "method", nil, nil,
		&ipc.Origin{Node: "1:0001.0000.0001", Authenticated: true})
	if err == nil {
		t.Error("expected 'service not started' error")
	}
}
