package appstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// supervisorLogName is the file the supervisor appends one JSON line
// per per-app lifecycle event to. Lives under each app's dir so
// `pilotctl appstore audit <id>` can read it without daemon glue.
const supervisorLogName = "supervisor.log"

// supervisorLogRotated is the single-step rotation target. On reaching
// maxAuditLogSize, writeAuditLine moves supervisor.log here (overwriting
// any prior copy) and starts fresh. Single-step keeps the design simple:
// worst-case footprint is 2 × maxAuditLogSize per app, plenty of history
// for an incident, and no log.2/log.3 chain to manage.
const supervisorLogRotated = "supervisor.log.1"

// maxAuditLogSize bounds each app's active audit log. A crash-looping
// app emits ~5 lines per failed spawn cycle (verify-fail / exit /
// spawn / spawn-fail / supervise-stop), each ~150B, so 10MB is
// thousands of crash cycles — more than enough for forensics.
const maxAuditLogSize = 10 * 1024 * 1024

// auditEvent is one line in the supervisor.log JSONL stream.
// AppID + EventType + At are always populated; the rest depends on type.
type auditEvent struct {
	At        time.Time `json:"at"`
	AppID     string    `json:"app"`
	Event     string    `json:"event"` // "spawn", "exit", "suspend", "verify-fail"
	PID       int       `json:"pid,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`     // pinned hash, recorded on spawn for traceability
	BinaryAt  string    `json:"binary_path,omitempty"`
}

// writeAuditLine appends one JSON-encoded event to the app's
// supervisor.log. Errors are logged to the structured logger but do
// not propagate — the audit channel is best-effort, never blocks
// lifecycle actions.
func (s *supervisor) writeAuditLine(a *installedApp, ev auditEvent) {
	ev.AppID = a.Manifest.ID
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	body, err := json.Marshal(&ev)
	if err != nil {
		s.logger.Printf("audit marshal: %v", err)
		return
	}
	body = append(body, '\n')
	path := filepath.Join(a.Dir, supervisorLogName)
	s.rotateAuditIfLarge(a.Dir)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		s.logger.Printf("audit open %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		s.logger.Printf("audit write %s: %v", path, err)
	}
}

// rotateAuditIfLarge renames supervisor.log → supervisor.log.1 when
// the active log has crossed the configured size threshold. The
// threshold defaults to maxAuditLogSize but can be lowered for tests
// via supervisor.cfg.AuditLogMaxBytes. Errors are logged but never
// fatal — forensics best-effort, never blocks the lifecycle write.
func (s *supervisor) rotateAuditIfLarge(appDir string) {
	max := int64(maxAuditLogSize)
	if s.cfg.AuditLogMaxBytes > 0 {
		max = s.cfg.AuditLogMaxBytes
	}
	active := filepath.Join(appDir, supervisorLogName)
	info, err := os.Stat(active)
	if err != nil {
		return // first write or perm issue — let the open handle it
	}
	if info.Size() < max {
		return
	}
	rotated := filepath.Join(appDir, supervisorLogRotated)
	// os.Rename replaces the destination atomically on Unix, so a
	// concurrent reader of the rotated path will see either the old
	// or the new one — never a partial file.
	if err := os.Rename(active, rotated); err != nil {
		s.logger.Printf("audit rotate %s → %s: %v", active, rotated, err)
	}
}

// supervisor manages the child-process lifecycle for every installed app
// and the IPC broker that lets external callers dispatch into them.
// One supervisor per daemon.
type supervisor struct {
	cfg    Config
	deps   Deps
	logger *log.Logger

	// mu guards installed + ready + crashes + appCancel.
	mu        sync.RWMutex
	installed map[string]*installedApp    // app_id → record
	ready     map[string]bool             // app_id → socket has appeared at least once
	crashes   map[string]*crashRecord     // app_id → sliding-window crash counter
	appCancel map[string]context.CancelFunc // app_id → cancel its per-app context (used to stop a supervise goroutine on detected uninstall)
}

func newSupervisor(cfg Config, deps Deps, logger *log.Logger) *supervisor {
	return &supervisor{
		cfg:       cfg,
		deps:      deps,
		logger:    logger,
		installed: map[string]*installedApp{},
		ready:     map[string]bool{},
		crashes:   map[string]*crashRecord{},
		appCancel: map[string]context.CancelFunc{},
	}
}

// crashLoopWindow + maxCrashesInWindow define when an app is judged to
// be stuck in a crash-loop. Exceed the cap and the supervisor stops
// respawning until either the daemon restarts or a future
// pilotctl-driven "appstore restart" command clears the suspended bit.
const (
	crashLoopWindow    = 60 * time.Second
	maxCrashesInWindow = 5
)

// crashRecord tracks recent process exits to detect crash-loops.
type crashRecord struct {
	times     []time.Time // recent crash timestamps within crashLoopWindow
	suspended bool        // true once max-in-window has been exceeded; no further respawn
}

// recordCrash registers an exit and returns whether the app is now
// suspended (i.e. its crash-loop budget is spent and the supervisor
// should not respawn it).
func (s *supervisor) recordCrash(appID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.crashes[appID]
	if !ok {
		rec = &crashRecord{}
		s.crashes[appID] = rec
	}
	now := time.Now()
	// Drop entries older than the window.
	cutoff := now.Add(-crashLoopWindow)
	keep := rec.times[:0]
	for _, t := range rec.times {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	rec.times = append(keep, now)
	if len(rec.times) > maxCrashesInWindow {
		rec.suspended = true
	}
	return rec.suspended
}

// isSuspended reports whether the app's restart budget is spent.
func (s *supervisor) isSuspended(appID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.crashes[appID]
	return ok && rec.suspended
}

// AppInfo is the public summary of one installed app, exposed via
// Service.Apps. Strips internal paths the daemon shouldn't expose.
type AppInfo struct {
	ID              string   `json:"id"`
	AppVersion      string   `json:"app_version"`
	ManifestVersion int      `json:"manifest_version"`
	Methods         []string `json:"methods"`
	Protection      string   `json:"protection"`
	Ready           bool     `json:"ready"`
	Suspended       bool     `json:"suspended,omitempty"` // crash-loop budget spent
}

// installedApp captures the on-disk state of one installed app — a pinned
// manifest plus the resolved paths under InstallRoot.
type installedApp struct {
	Manifest   *manifest.Manifest
	Dir        string // <InstallRoot>/<app_id>
	BinaryPath string // Dir + manifest.Binary.Path
	SocketPath string // Dir/app.sock
	DBPath     string // Dir/data.db
	IDPath     string // Dir/identity.json
}

// scanInstalled walks InstallRoot, reads each `<app>/manifest.json`, and
// returns the verified-by-syntax set. Sha256 verification is per-launch
// (in run()), not per-scan, so a corrupted binary surfaces at the right
// time.
func (s *supervisor) scanInstalled() ([]*installedApp, error) {
	entries, err := os.ReadDir(s.cfg.InstallRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*installedApp
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.cfg.InstallRoot, e.Name())
		mfPath := filepath.Join(dir, "manifest.json")
		data, err := os.ReadFile(mfPath)
		if err != nil {
			s.logger.Printf("skip %s: read manifest: %v", e.Name(), err)
			continue
		}
		m, err := manifest.Parse(data)
		if err != nil {
			s.logger.Printf("skip %s: parse: %v", e.Name(), err)
			continue
		}
		if errs := m.Validate(); len(errs) != 0 {
			s.logger.Printf("skip %s: invalid manifest: %v", e.Name(), errs[0])
			continue
		}
		// Reject path traversal in manifest.binary.path. Without this
		// a manifest containing binary.path="../../../bin/sh" (or any
		// "..") would resolve OUTSIDE the app's install dir, letting
		// a hostile or compromised manifest exec arbitrary host
		// binaries under the daemon's uid.
		binaryPath, err := resolveUnder(dir, m.Binary.Path)
		if err != nil {
			s.logger.Printf("skip %s: binary path %q escapes app dir: %v", e.Name(), m.Binary.Path, err)
			continue
		}
		// Reject symlinks on the resolved binary. An attacker with
		// write access to the app dir can drop a symlink that points
		// to /bin/sh, /usr/bin/curl, or any other host binary. Lstat
		// (not Stat) so we see the symlink itself, not its target.
		// Non-existent paths are fine here — spawn() will produce the
		// right error when it tries to exec. We only refuse a path
		// that EXISTS AS A SYMLINK.
		if fi, err := os.Lstat(binaryPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			s.logger.Printf("skip %s: binary path %s is a symlink (refusing)", e.Name(), binaryPath)
			continue
		}
		out = append(out, &installedApp{
			Manifest:   m,
			Dir:        dir,
			BinaryPath: binaryPath,
			SocketPath: filepath.Join(dir, "app.sock"),
			DBPath:     filepath.Join(dir, "data.db"),
			IDPath:     filepath.Join(dir, "identity.json"),
		})
	}
	return out, nil
}

// registerInstalled records the supplied apps in the supervisor's
// in-memory table. Called by Service.Start *before* the supervise
// goroutine kicks off, so callers of Apps() / Call() see the right
// set the moment Start returns (no race against run()'s startup).
func (s *supervisor) registerInstalled(apps []*installedApp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range apps {
		s.installed[a.Manifest.ID] = a
	}
}

// defaultRescanInterval is the supervisor's polling cadence for
// newly-installed apps under InstallRoot. Tests can override via
// Config.RescanInterval — production runs use 30s, fast enough that
// `pilotctl appstore install` becomes visible without daemon restart
// but slow enough that the directory walk isn't measurable load.
const defaultRescanInterval = 30 * time.Second

// run is the supervisor loop. It spawns + respawns each child until
// ctx is canceled. Additionally periodically re-walks InstallRoot to
// pick up apps installed while the daemon is already running AND to
// notice apps whose dir disappeared (e.g. via `pilotctl appstore
// uninstall`). Each app gets its own derived context so the rescan
// can stop a single goroutine without affecting the rest.
func (s *supervisor) run(ctx context.Context, apps []*installedApp) {
	var wg sync.WaitGroup
	startOne := func(a *installedApp) {
		appCtx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.appCancel[a.Manifest.ID] = cancel
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.superviseOne(appCtx, a)
		}()
	}
	for _, a := range apps {
		startOne(a)
	}

	// Rescan loop. Lives in its own goroutine so wg.Wait below sees
	// every Add before being called — Go's WaitGroup forbids
	// concurrent Add+Wait, so rescanDone gates the order: rescan
	// goroutine exits first (no more Adds), then we wg.Wait the
	// supervise goroutines.
	rescanDone := make(chan struct{})
	go func() {
		defer close(rescanDone)
		interval := s.cfg.RescanInterval
		if interval <= 0 {
			interval = defaultRescanInterval
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, a := range s.rescanForNew() {
					startOne(a)
				}
				s.rescanForGone()
				for _, a := range s.rescanForResume() {
					startOne(a)
				}
			}
		}
	}()

	<-rescanDone
	wg.Wait()
}

// rescanForNew walks InstallRoot fresh and returns any app that's
// present on disk but not yet in the in-memory installed map. Found
// entries are registered into the map under the supervisor's lock so
// concurrent Apps()/Call() reads see them as soon as a supervise
// goroutine starts. Errors are logged and treated as "no new apps";
// a transient FS issue shouldn't kill the supervisor.
func (s *supervisor) rescanForNew() []*installedApp {
	apps, err := s.scanInstalled()
	if err != nil {
		s.logger.Printf("rescan: %v", err)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []*installedApp
	for _, a := range apps {
		if _, exists := s.installed[a.Manifest.ID]; exists {
			continue
		}
		s.installed[a.Manifest.ID] = a
		fresh = append(fresh, a)
		s.logger.Printf("rescan: discovered new app id=%s dir=%s", a.Manifest.ID, a.Dir)
	}
	return fresh
}

// rescanForGone is the rescan's other half: detect installed apps
// whose dir has disappeared (typically via `pilotctl appstore
// uninstall`) and cancel their supervise goroutines so they don't
// sit forever in verify-fail backoff. Removed from the in-memory
// installed map so Apps()/Call() stop reporting them immediately.
//
// Uses os.Stat against each known installed-app's Dir rather than
// re-walking the install root, because the install root could
// transiently be missing during a `--force` install's rename
// dance — single-app stat is more precise.
func (s *supervisor) rescanForGone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.installed {
		if _, err := os.Stat(filepath.Join(a.Dir, "manifest.json")); err == nil {
			continue // dir + manifest both still present → still installed
		}
		// Cancel the supervise goroutine; it exits via its existing
		// ctx.Done handling and writes its deferred supervise-stop
		// audit line (with reason "context canceled") to the app
		// dir if it still exists, or no-ops if it doesn't.
		if cancel, ok := s.appCancel[id]; ok {
			cancel()
			delete(s.appCancel, id)
		}
		delete(s.installed, id)
		delete(s.ready, id)
		s.logger.Printf("rescan: app id=%s removed from disk; supervise goroutine canceled", id)
	}
}

// suspendedMarkerName is the sentinel the supervisor writes when an
// app's crash-loop budget runs out. Sits next to manifest.json so
// `pilotctl appstore list` can detect suspended state purely from
// disk (no daemon IPC needed). The marker is cleared when
// rescanForResume consumes a `.resume` request.
const suspendedMarkerName = ".suspended"

// resumeMarkerName is the sentinel pilotctl drops into an app's dir
// to ask the supervisor to clear suspension and restart watching.
// Lives under each app's dir alongside manifest.json and supervisor.log
// — same mode (0644) as manifest.json, so it's a same-user signal
// rather than a privilege escalation surface.
const resumeMarkerName = ".resume"

// rescanForResume walks installed apps for the .resume sentinel
// dropped by `pilotctl appstore restart <id>`. On detect: deletes
// the marker (idempotent), clears the crash-loop record so the
// app isn't immediately re-suspended on first failure, removes any
// stale cancel func, and returns the apps that need a fresh
// supervise goroutine. The caller (rescan loop) is responsible for
// actually launching the goroutine via startOne so wg accounting
// stays correct.
//
// Sentinel-file design (vs an IPC method): pilotctl talks to apps
// over their unix sockets, not the supervisor. A file-based signal
// is the lowest-friction option that doesn't require a new daemon
// socket. The marker is removed on consume so a future tick can't
// re-trigger; if multiple ticks fire before the rescan picks it up,
// they collapse to one resume — exactly what users want.
func (s *supervisor) rescanForResume() []*installedApp {
	s.mu.Lock()
	defer s.mu.Unlock()
	var resumed []*installedApp
	for id, a := range s.installed {
		markerPath := filepath.Join(a.Dir, resumeMarkerName)
		if _, err := os.Stat(markerPath); err != nil {
			continue
		}
		// Consume the marker first so a partial failure doesn't loop.
		if err := os.Remove(markerPath); err != nil {
			s.logger.Printf("rescan: app id=%s: remove resume marker: %v", id, err)
			continue
		}
		// Clear the crash record so the new supervise goroutine
		// starts with a fresh window. Also drop the stale cancel —
		// the old goroutine has already returned (suspended apps
		// don't have live goroutines), but the cancel func may
		// still be in the map.
		delete(s.crashes, id)
		delete(s.appCancel, id)
		// Clear the suspended marker so list/status reflect the new state.
		// Ignore "not exist" — could happen if the operator dropped
		// .resume before the supervisor finished writing .suspended.
		if err := os.Remove(filepath.Join(a.Dir, suspendedMarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.logger.Printf("rescan: app id=%s: remove suspended marker: %v", id, err)
		}
		s.writeAuditLine(a, auditEvent{Event: "resume", Reason: "operator requested via .resume marker"})
		s.logger.Printf("rescan: app id=%s resumed by operator request", id)
		resumed = append(resumed, a)
	}
	return resumed
}

// superviseOne runs one app forever, respawning on exit until ctx is canceled.
func (s *supervisor) superviseOne(ctx context.Context, a *installedApp) {
	// Mark the start + end of supervision. The pair tells forensics
	// "between T0 and T1 the daemon was actively watching this app";
	// the absence of supervise-stop with a present supervise-start
	// means a hard daemon crash (defer never ran).
	s.writeAuditLine(a, auditEvent{Event: "supervise-start", SHA256: a.Manifest.Binary.SHA256, BinaryAt: a.BinaryPath})
	// Clear any stale .suspended marker. Two cases land here:
	//   - daemon restart: a prior process suspended this app and left
	//     the marker; the new process is starting fresh with empty
	//     crashes state, so the marker no longer reflects reality.
	//   - rescanForResume already deleted it (no-op via ErrNotExist).
	// Either way, the invariant after this point is: supervise goroutine
	// is live iff .suspended is absent.
	if err := os.Remove(filepath.Join(a.Dir, suspendedMarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Printf("app=%s: clear stale suspended marker: %v", a.Manifest.ID, err)
	}
	defer func() {
		reason := "context canceled"
		if ctx.Err() == nil {
			// Every non-ctx return path in this function is the
			// crash-loop suspension; if a new return path is added
			// without its own reason, this fallback still tells
			// forensics the supervisor exited under its own steam.
			reason = "suspended (crash-loop cap reached)"
		}
		s.writeAuditLine(a, auditEvent{Event: "supervise-stop", Reason: reason})
	}()
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := s.verifyBinary(a); err != nil {
			s.logger.Printf("app=%s: verify: %v — refusing to spawn", a.Manifest.ID, err)
			s.writeAuditLine(a, auditEvent{Event: "verify-fail", Reason: err.Error(), SHA256: a.Manifest.Binary.SHA256, BinaryAt: a.BinaryPath})
			// A bad sha256 is fatal for this app; wait + retry in case
			// the user fixes it (e.g. re-install).
			select {
			case <-ctx.Done():
				return
			case <-time.After(maxBackoff):
				continue
			}
		}
		exitCode := s.spawn(ctx, a)
		s.markNotReady(a.Manifest.ID)
		s.writeAuditLine(a, auditEvent{Event: "exit", ExitCode: exitCode})
		if ctx.Err() != nil {
			return
		}
		if suspended := s.recordCrash(a.Manifest.ID); suspended {
			s.logger.Printf("app=%s exited (code=%d) — SUSPENDED (>%d crashes in %s); not respawning until daemon restart",
				a.Manifest.ID, exitCode, maxCrashesInWindow, crashLoopWindow)
			s.writeAuditLine(a, auditEvent{Event: "suspend", Reason: fmt.Sprintf(">%d crashes in %s", maxCrashesInWindow, crashLoopWindow)})
			// Drop a sentinel file so `pilotctl appstore list` (which
			// reads the install root without daemon IPC) can detect
			// suspension purely from disk. Best-effort: a failure to
			// touch the file is a log line, not a fatal — the audit
			// log still records the event canonically.
			markerPath := filepath.Join(a.Dir, suspendedMarkerName)
			if err := os.WriteFile(markerPath, nil, 0o600); err != nil {
				s.logger.Printf("app=%s: write suspended marker: %v", a.Manifest.ID, err)
			}
			return
		}
		s.logger.Printf("app=%s exited (code=%d) — restart in %s", a.Manifest.ID, exitCode, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// verifyBinary sha256-checks the binary against the pinned hash in the
// manifest. Matches what the architecture's launch-time trust check
// requires (manifest pins sha256, daemon re-verifies on every launch).
func (s *supervisor) verifyBinary(a *installedApp) error {
	f, err := os.Open(a.BinaryPath)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash binary: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != a.Manifest.Binary.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, a.Manifest.Binary.SHA256)
	}
	return nil
}

// spawn launches the app's binary, blocks until it exits, returns the
// exit code (or -1 on error). The caller is responsible for restart logic.
//
// Marks the app "ready" once its socket has appeared, so concurrent
// Call() invocations can know when to dial.
func (s *supervisor) spawn(ctx context.Context, a *installedApp) int {
	// Drop a stale socket if a previous instance crashed without cleaning.
	if _, err := os.Stat(a.SocketPath); err == nil {
		_ = os.Remove(a.SocketPath)
	}

	// Pass the pinned manifest path through. Cap-aware apps (the
	// wallet, currently) use this to activate runtime spend caps
	// declared in the grants block; binaries that don't recognize
	// --manifest can ignore it (the Go flag package errors with a
	// clear "flag provided but not defined" — every app installed
	// via the app store is expected to accept the standard lifecycle
	// flags, of which --manifest is now part).
	args := []string{
		"--addr", daemonAddrFromDeps(s.deps),
		"--db", a.DBPath,
		"--socket", a.SocketPath,
		"--identity", a.IDPath,
		"--manifest", filepath.Join(a.Dir, "manifest.json"),
		"--cap-state", filepath.Join(a.Dir, "cap-state.jsonl"),
	}
	cmd := exec.CommandContext(ctx, a.BinaryPath, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group → clean SIGTERM
	s.logger.Printf("app=%s spawn binary=%s socket=%s", a.Manifest.ID, a.BinaryPath, a.SocketPath)

	if err := cmd.Start(); err != nil {
		s.logger.Printf("app=%s start: %v", a.Manifest.ID, err)
		s.writeAuditLine(a, auditEvent{Event: "spawn-fail", Reason: err.Error(), BinaryAt: a.BinaryPath})
		return -1
	}
	s.logger.Printf("app=%s started pid=%d", a.Manifest.ID, cmd.Process.Pid)
	// Apply per-platform resource limits to the freshly-started
	// child. Best-effort: a failure logs but doesn't kill the spawn
	// (OS-wide ulimits still apply). Linux uses prlimit(2) for a
	// RLIMIT_NOFILE cap; other platforms log a "not enforced" line.
	applyChildResourceLimits(cmd.Process.Pid, s.logger)
	s.writeAuditLine(a, auditEvent{Event: "spawn", PID: cmd.Process.Pid, SHA256: a.Manifest.Binary.SHA256, BinaryAt: a.BinaryPath})

	// Watch for the socket to appear; once it does, mark ready.
	go s.waitReady(ctx, a, 3*time.Second)

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		s.logger.Printf("app=%s wait: %v", a.Manifest.ID, err)
		return -1
	}
	return 0
}

// waitReady polls the spawned app's socket until either it appears or
// the timeout elapses. On success marks the app ready, which lets
// Call() know it's safe to dial.
func (s *supervisor) waitReady(ctx context.Context, a *installedApp, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return
		}
		if _, err := os.Stat(a.SocketPath); err == nil {
			s.markReady(a.Manifest.ID)
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	s.logger.Printf("app=%s socket did not appear within %s", a.Manifest.ID, timeout)
}

func (s *supervisor) markReady(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready[appID] = true
}

func (s *supervisor) markNotReady(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ready, appID)
}

// ── public broker surface ──────────────────────────────────────────────

// ErrAppNotInstalled is returned by Call/Apps lookups for unknown app IDs.
var ErrAppNotInstalled = errors.New("appstore: app not installed")

// ErrAppNotReady is returned by Call when the app's socket hasn't
// appeared yet (still starting up, or it crashed and hasn't respawned).
var ErrAppNotReady = errors.New("appstore: app not ready")

// Apps returns the public-shaped summary of every installed app, in
// arbitrary order. Used by pilotctl's `appstore list` and by other
// apps that want to introspect what's available.
func (s *supervisor) Apps() []AppInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AppInfo, 0, len(s.installed))
	for id, app := range s.installed {
		suspended := false
		if rec, ok := s.crashes[id]; ok {
			suspended = rec.suspended
		}
		out = append(out, AppInfo{
			ID:              id,
			AppVersion:      app.Manifest.AppVersion,
			ManifestVersion: app.Manifest.ManifestVersion,
			Methods:         append([]string(nil), app.Manifest.Exposes...),
			Protection:      app.Manifest.Protection,
			Ready:           s.ready[id],
			Suspended:       suspended,
		})
	}
	return out
}

// Get returns the installed app record for an id, or nil if unknown.
// Internal helper for tests and the broker.
func (s *supervisor) Get(appID string) *installedApp {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.installed[appID]
}

// Call dispatches method+args into the named installed app via its
// app.sock. The connection is dialed per-call — simple and lets the
// app's own concurrency handle multiple in-flight calls. Returns
// ErrAppNotInstalled / ErrAppNotReady for the obvious failure modes,
// otherwise propagates the app's IPC response (or its error).
func (s *supervisor) Call(ctx context.Context, appID, method string, args, out any) error {
	s.mu.RLock()
	app, ok := s.installed[appID]
	ready := s.ready[appID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrAppNotInstalled, appID)
	}
	if !ready {
		// Give it a brief moment in case it just spawned.
		if !s.awaitReady(ctx, appID, 1*time.Second) {
			return fmt.Errorf("%w: %s", ErrAppNotReady, appID)
		}
	}

	// Honour the caller's deadline at the dial step.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if dl, ok := ctx.Deadline(); ok {
		dialer.Deadline = dl
	}
	conn, err := dialer.DialContext(ctx, "unix", app.SocketPath)
	if err != nil {
		return fmt.Errorf("appstore call %s: dial: %w", appID, err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return ipc.Call(conn, method, args, out)
}

// awaitReady polls the ready bit for app until it flips true or the
// deadline elapses. Returns whether ready was observed.
func (s *supervisor) awaitReady(ctx context.Context, appID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return false
		}
		s.mu.RLock()
		ok := s.ready[appID]
		s.mu.RUnlock()
		if ok {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

// ── identity hookup ────────────────────────────────────────────────────

// daemonAddrFromDeps reads the daemon's pilot address out of Deps.
// Uses Go's structural typing so the supervisor doesn't import the real
// coreapi package — any Identity-like value with an Address() string
// method works (which is exactly the coreapi.Identity contract).
//
// Falls back to a sentinel when no Identity is wired (tests that pass
// an empty Deps); the sentinel is intentionally non-routable so a
// production misconfiguration fails fast rather than silently using
// the wrong address.
type identityAddresser interface {
	Address() string
}

func daemonAddrFromDeps(deps Deps) string {
	if deps.Identity != nil {
		if id, ok := deps.Identity.(identityAddresser); ok {
			if addr := id.Address(); addr != "" {
				return addr
			}
		}
	}
	return "0:0001.0000.0000"
}

// resolveUnder joins `rel` onto `base`, cleans it, and verifies the
// result is contained inside `base`. Returns an error otherwise.
//
// Prevents the manifest path-traversal vector: filepath.Join itself
// does not block `..` traversal; a manifest with binary.path =
// "../../../bin/sh" would resolve outside the app's install dir and
// let a hostile manifest exec arbitrary host binaries under the
// daemon's UID.
func resolveUnder(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path not permitted")
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("abs base: %w", err)
	}
	joined := filepath.Clean(filepath.Join(absBase, rel))
	// Ensure joined is `absBase` itself OR `absBase + "/" + ...`.
	if joined != absBase && !strings.HasPrefix(joined, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes %s", absBase)
	}
	return joined, nil
}
