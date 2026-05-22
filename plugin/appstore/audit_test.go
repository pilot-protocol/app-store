package appstore

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteAuditLineAppendsJSONL hits the supervisor's audit channel
// directly: write three events, read the file back, confirm each line
// is a valid JSON event with the right fields.
func TestWriteAuditLineAppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	app := &installedApp{
		Dir:      dir,
		Manifest: parseDummyManifest(t, "io.test.app"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))

	sup.writeAuditLine(app, auditEvent{Event: "spawn", PID: 1234, SHA256: "abc"})
	sup.writeAuditLine(app, auditEvent{Event: "exit", ExitCode: 1})
	sup.writeAuditLine(app, auditEvent{Event: "suspend", Reason: "too-many-crashes"})

	f, err := os.Open(filepath.Join(dir, supervisorLogName))
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	var events []auditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev auditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("unmarshal line %q: %v", scanner.Text(), err)
		}
		events = append(events, ev)
	}
	if scanner.Err() != nil {
		t.Fatalf("scan: %v", scanner.Err())
	}

	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	if events[0].Event != "spawn" || events[0].PID != 1234 || events[0].AppID != "io.test.app" {
		t.Errorf("spawn event: %+v", events[0])
	}
	if events[1].Event != "exit" || events[1].ExitCode != 1 {
		t.Errorf("exit event: %+v", events[1])
	}
	if events[2].Event != "suspend" || events[2].Reason != "too-many-crashes" {
		t.Errorf("suspend event: %+v", events[2])
	}
	// All events must carry a non-zero timestamp.
	for i, ev := range events {
		if ev.At.IsZero() {
			t.Errorf("event %d missing timestamp", i)
		}
	}
}

// TestAuditLogPermissions confirms the log file is 0600 — same threat
// model as the identity file. Audit data may include PIDs and
// timestamps that are useful for forensics; 0600 keeps it owner-only.
func TestAuditLogPermissions(t *testing.T) {
	dir := t.TempDir()
	app := &installedApp{Dir: dir, Manifest: parseDummyManifest(t, "io.test.app")}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))
	sup.writeAuditLine(app, auditEvent{Event: "spawn", PID: 1})

	info, err := os.Stat(filepath.Join(dir, supervisorLogName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode: %o, want 0600", info.Mode().Perm())
	}
}

// TestAuditLogRotatesAtSizeThreshold confirms that once the active
// supervisor.log crosses cfg.AuditLogMaxBytes, the next write triggers
// rotation: the old content moves to supervisor.log.1, the active
// log restarts fresh. Without this, a crash-looping app's audit log
// grows unbounded.
func TestAuditLogRotatesAtSizeThreshold(t *testing.T) {
	dir := t.TempDir()
	app := &installedApp{
		Dir:      dir,
		Manifest: parseDummyManifest(t, "io.test.app"),
	}
	// Tiny rotation threshold so we trip it in a handful of lines.
	sup := newSupervisor(Config{InstallRoot: dir, AuditLogMaxBytes: 200}, Deps{}, newQuietLogger(t))

	// Write enough lines that the active log crosses 200 bytes. Each
	// line is roughly 100 bytes JSONL, so 5 lines is plenty.
	for i := 0; i < 8; i++ {
		sup.writeAuditLine(app, auditEvent{Event: "spawn", PID: i, SHA256: "abc"})
	}

	// supervisor.log.1 must exist (rotated content), supervisor.log
	// must also exist (recent content), and both should be < 2 × max
	// (no buildup beyond the rotation guarantee).
	rotatedInfo, err := os.Stat(filepath.Join(dir, supervisorLogRotated))
	if err != nil {
		t.Fatalf("rotated log missing: %v", err)
	}
	activeInfo, err := os.Stat(filepath.Join(dir, supervisorLogName))
	if err != nil {
		t.Fatalf("active log missing: %v", err)
	}
	if rotatedInfo.Size() == 0 {
		t.Errorf("rotated log is empty — content was lost during rotation")
	}
	if activeInfo.Size() == 0 {
		t.Errorf("active log is empty after rotation — new writes didn't land")
	}
	// Combined size shouldn't massively exceed 2 × threshold even
	// with the most-recent line just barely over.
	if combined := rotatedInfo.Size() + activeInfo.Size(); combined > 4*200 {
		t.Errorf("combined log size %d > 4 × threshold (200) — rotation isn't bounding growth", combined)
	}
	// Permission check survives rotation: both files must remain 0600.
	for _, info := range []os.FileInfo{rotatedInfo, activeInfo} {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("post-rotation log mode %#o, want 0600", perm)
		}
	}
}

// TestSuperviseStartClearsStaleSuspendedMarker confirms the
// daemon-restart hygiene: if a previous process suspended an app and
// left the `.suspended` sentinel on disk, a fresh `superviseOne`
// invocation (under a new daemon with empty crashes state) must
// remove the stale marker — otherwise `pilotctl appstore list`
// would keep showing SUSPENDED while the supervisor is actually
// watching the app.
func TestSuperviseStartClearsStaleSuspendedMarker(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.test.app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Plant a stale marker as if a prior process suspended this app.
	stale := filepath.Join(appDir, ".suspended")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	app := &installedApp{
		Dir:        appDir,
		BinaryPath: filepath.Join(appDir, "missing-binary"),
		Manifest:   parseDummyManifest(t, "io.test.app"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled up-front so superviseOne returns immediately after the start-of-function cleanup
	done := make(chan struct{})
	go func() {
		sup.superviseOne(ctx, app)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseOne did not return within 2s of canceled ctx")
	}

	// Marker should be gone — supervise goroutine entered, cleared it
	// before returning via the ctx-Done branch.
	if _, err := os.Stat(stale); err == nil {
		t.Errorf("stale .suspended marker still present after superviseOne entry; supervisor will lie to list")
	}
}

// TestSuperviseStartAndStopAreAudited drives superviseOne with a
// missing-binary app and an already-canceled context so the loop
// returns immediately. The pair of supervise-start / supervise-stop
// audit lines must appear, sandwiching any verify-fail / exit events.
// Forensics need this to distinguish "supervisor was watching but the
// binary was never spawnable" from "supervisor never saw this app".
func TestSuperviseStartAndStopAreAudited(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "io.test.app")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	app := &installedApp{
		Dir:        appDir,
		BinaryPath: filepath.Join(appDir, "missing-binary"),
		Manifest:   parseDummyManifest(t, "io.test.app"),
	}
	sup := newSupervisor(Config{InstallRoot: dir}, Deps{}, newQuietLogger(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel up-front so the loop's ctx-check returns before spawning anything

	done := make(chan struct{})
	go func() {
		sup.superviseOne(ctx, app)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseOne did not return within 2s of canceled ctx")
	}

	f, err := os.Open(filepath.Join(appDir, supervisorLogName))
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	var events []auditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev auditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("unmarshal: %v", err)
			continue
		}
		events = append(events, ev)
	}
	if len(events) < 2 {
		t.Fatalf("want at least 2 events, got %d: %+v", len(events), events)
	}
	if events[0].Event != "supervise-start" {
		t.Errorf("first event %q, want supervise-start", events[0].Event)
	}
	if events[0].SHA256 != app.Manifest.Binary.SHA256 {
		t.Errorf("supervise-start sha256 %q, want %q", events[0].SHA256, app.Manifest.Binary.SHA256)
	}
	last := events[len(events)-1]
	if last.Event != "supervise-stop" {
		t.Errorf("last event %q, want supervise-stop", last.Event)
	}
	if last.Reason != "context canceled" {
		t.Errorf("supervise-stop reason %q, want %q", last.Reason, "context canceled")
	}
}
