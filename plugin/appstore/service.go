// Package appstore is the coreapi.Service shim that hosts the app store
// inside the pilot daemon. It implements coreapi.Service (Name/Order/Start/
// Stop) and wraps the supervisor that spawns + brokers every installed app.
//
// The shim does not import the daemon's coreapi package directly, so the
// app-store module stays self-buildable. The Service type's method shapes
// are nominally identical to coreapi.Service; the daemon's main.go can
// register *Service against the interface without an explicit adapter as
// long as the type signatures stay in sync. (See INTEGRATION.md for the
// contract.)
package appstore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config carries the integration-time settings. Passed by the daemon's
// main.go composition root; defaults are picked up when fields are zero.
type Config struct {
	// InstallRoot is where the app store keeps each installed app's
	// pinned manifest, binary, data, identity, and audit log.
	// Default: ~/.pilot/apps.
	InstallRoot string

	// CatalogPubkey is the ed25519 public key the app store uses to
	// verify the signed catalog Merkle root. In production this is
	// compile-time-embedded into the daemon binary (see
	// EmbeddedCatalogPubkey). For dev mode, leave zero and pass a
	// dev key via NewServiceWithKey.
	CatalogPubkey []byte

	// Logger optionally redirects internal messages. When nil the
	// service logs via the standard log package.
	Logger *log.Logger

	// RescanInterval controls how often the supervisor re-walks
	// InstallRoot looking for newly-landed apps (e.g. dropped by
	// `pilotctl appstore install` while the daemon is running).
	// Zero defaults to 30s. Set very short (e.g. 100ms) in tests.
	RescanInterval time.Duration

	// AuditLogMaxBytes is the per-app supervisor.log size threshold
	// at which a single-step rotation fires (active → .1). Zero
	// defaults to maxAuditLogSize (10MB). Tests set this low to
	// exercise the rotation path without writing megabytes.
	AuditLogMaxBytes int64
}

// EmbeddedCatalogPubkey is the production trust anchor for the catalog.
// REPLACE with the real key before release; the placeholder here is the
// all-zeros key so a misconfigured build refuses to verify anything (any
// real signature will fail against zero).
var EmbeddedCatalogPubkey = make([]byte, 32)

// catalogPubkeyIsPlaceholder reports whether the supplied catalog
// trust anchor is the all-zeros fail-closed default (or empty/nil).
// Used at Start to warn operators they're running with a dev-mode
// trust anchor — production builds MUST replace EmbeddedCatalogPubkey.
func catalogPubkeyIsPlaceholder(pk []byte) bool {
	if len(pk) == 0 {
		return true
	}
	for _, b := range pk {
		if b != 0 {
			return false
		}
	}
	return true
}

// Service implements coreapi.Service for the app store.
type Service struct {
	cfg     Config
	logger  *log.Logger
	sup     *supervisor // started in Start; nil before then
	cancel  context.CancelFunc
	doneCh  chan struct{}
	startMu sync.Mutex
}

// NewService constructs a Service using cfg. Defaults are filled in.
func NewService(cfg Config) *Service {
	if cfg.InstallRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.InstallRoot = filepath.Join(home, ".pilot", "apps")
		} else {
			cfg.InstallRoot = ".pilot/apps"
		}
	}
	if cfg.CatalogPubkey == nil {
		cfg.CatalogPubkey = EmbeddedCatalogPubkey
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "appstore ", log.LstdFlags|log.Lmicroseconds)
	}
	return &Service{cfg: cfg, logger: logger}
}

// Name returns the plugin identifier reported to the runtime registry.
func (s *Service) Name() string { return "appstore" }

// Order returns the lifecycle priority. 120 = application layer, started
// after foundation (10-49) and trust (50-79), before sidecars (200+).
// Stop runs in reverse, so by the time we stop, peer plugins still up.
func (s *Service) Order() int { return 120 }

// Deps is the duck-typed shape of coreapi.Deps the daemon hands plugins.
// Kept independent of the real coreapi package so app-store stays
// self-buildable; the field names + signatures must match
// pkg/coreapi/lifecycle.go exactly.
//
// When the daemon's main.go registers *Service it passes the real coreapi.Deps;
// Go's structural typing makes this work as long as the methods used here
// are present on the real types.
type Deps struct {
	Streams  any // coreapi.Streams — Dial, Listen, SendDatagram
	Identity any // coreapi.Identity — NodeID, Address, PublicKey, Sign
	Resolver any
	Events   any // coreapi.EventBus — Publish, Subscribe
	Logger   any
	Trust    any
}

// Start scans InstallRoot for installed apps, verifies each binary's
// pinned sha256, spawns the child processes, and parks an IPC connection
// per app for broker forwarding. Returns the first hard failure that
// would leave the daemon in an unhealthy state; per-app failures only
// log and continue (one bad app shouldn't sink the daemon).
//
// In tick 5 this is a skeleton: directory walk + log lines, no actual
// spawn. The supervisor wire-up happens in tick 6 when we have a real
// integration test against the daemon's coreapi.
func (s *Service) Start(ctx context.Context, deps Deps) error {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.sup != nil {
		return errors.New("appstore: already started")
	}

	if err := os.MkdirAll(s.cfg.InstallRoot, 0o700); err != nil {
		return fmt.Errorf("appstore: install root: %w", err)
	}

	// Loud warning when the compile-time-embedded catalog trust
	// anchor is still the all-zeros fail-closed placeholder. The
	// architecture's trust chain relies on this key to verify the
	// signed catalog Merkle root; a dev/test build is fine, but
	// shipping with an all-zeros key means catalog signatures can
	// never be authenticated. Surfacing this at Start lets an
	// operator catch a misbuilt release before any user-visible
	// install completes.
	if catalogPubkeyIsPlaceholder(s.cfg.CatalogPubkey) {
		s.logger.Printf("WARNING: dev-mode trust anchor — CatalogPubkey is the all-zeros placeholder; signed catalogs will NOT verify. Replace EmbeddedCatalogPubkey for production builds.")
	}

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.doneCh = make(chan struct{})

	s.sup = newSupervisor(s.cfg, deps, s.logger)
	apps, err := s.sup.scanInstalled()
	if err != nil {
		cancel()
		return fmt.Errorf("appstore: scan: %w", err)
	}
	// Populate the in-memory table synchronously so Apps()/Call() see
	// the set the moment Start returns — no race against the supervise
	// goroutine starting up.
	s.sup.registerInstalled(apps)
	s.logger.Printf("starting: install_root=%s installed_apps=%d", s.cfg.InstallRoot, len(apps))

	go func() {
		defer close(s.doneCh)
		s.sup.run(runCtx, apps)
	}()
	return nil
}

// Stop signals the supervisor to shut down and waits up to the ctx's
// deadline (or 5s if no deadline set) for all child processes to exit.
func (s *Service) Stop(ctx context.Context) error {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.sup == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.doneCh:
		s.sup = nil
		return nil
	case <-ctx.Done():
		s.logger.Printf("stop: ctx deadline reached before drain")
		return ctx.Err()
	}
}

// ── public broker surface ──────────────────────────────────────────────

// Apps returns a summary of every installed app the service is currently
// supervising. Returns nil before Start has run.
func (s *Service) Apps() []AppInfo {
	s.startMu.Lock()
	sup := s.sup
	s.startMu.Unlock()
	if sup == nil {
		return nil
	}
	return sup.Apps()
}

// Call dispatches method+args into the named installed app via its
// app.sock. This is the broker entry point that lets other plugins,
// the daemon, or pilotctl talk to any installed app's IPC surface
// without dialing the socket directly.
//
// Returns ErrAppNotInstalled when the app id is unknown, ErrAppNotReady
// when the spawned process hasn't bound its socket yet, or whatever
// error the app's own IPC handler returned.
func (s *Service) Call(ctx context.Context, appID, method string, args, out any) error {
	s.startMu.Lock()
	sup := s.sup
	s.startMu.Unlock()
	if sup == nil {
		return errors.New("appstore: service not started")
	}
	return sup.Call(ctx, appID, method, args, out)
}

// CallFrom is the cross-app broker entry point. callerID identifies the
// installed app making the request; the supervisor authorizes the call
// against that app's manifest grants (it must declare an `ipc.call` grant
// targeting "<appID>.<method>"). Pass an empty callerID for trusted
// daemon/pilotctl calls — see Call.
//
// Returns ErrAppNotInstalled, ErrMethodNotExposed, ErrGrantMissing, or
// ErrAppNotReady for the gate failures; otherwise the app's IPC response.
func (s *Service) CallFrom(ctx context.Context, callerID, appID, method string, args, out any) error {
	s.startMu.Lock()
	sup := s.sup
	s.startMu.Unlock()
	if sup == nil {
		return errors.New("appstore: service not started")
	}
	return sup.CallFrom(ctx, callerID, appID, method, args, out)
}
