package appstore

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A dir in the install root with no manifest.json is not an install: an app
// run outside the daemon can keep its state there (the wallet binary keeps
// identity-evm.json in ~/.pilot/apps/io.pilot.wallet). The rescan runs every
// 2 s, and it logged the dir on every tick: 1,574 times in under an hour on
// one Mac. It is logged once, and left alone.
func TestScanInstalled_DirWithoutManifestIsLoggedOnce(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	state := filepath.Join(root, "io.pilot.wallet", "identity-evm.json")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte(`{"key":"kept"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, log.New(&logs, "", 0))
	for i := 0; i < 5; i++ {
		apps, err := sup.scanInstalled()
		if err != nil || len(apps) != 0 {
			t.Fatalf("scan %d: %d apps, %v; want none", i, len(apps), err)
		}
	}
	if n := strings.Count(logs.String(), "skip io.pilot.wallet: no manifest.json"); n != 1 {
		t.Fatalf("logged %d times over 5 scans, want once:\n%s", n, logs.String())
	}
	if b, err := os.ReadFile(state); err != nil || string(b) != `{"key":"kept"}` {
		t.Fatalf("the app's state file was touched: %q, %v", b, err)
	}
}

// Every skip reason is logged once per dir, and again only when the reason
// changes (here: a manifest that stops parsing differently).
func TestScanInstalled_SkipIsLoggedAgainOnlyWhenItsReasonChanges(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mf := filepath.Join(root, "io.test.broken", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(mf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mf, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, log.New(&logs, "", 0))
	scan := func() {
		t.Helper()
		if _, err := sup.scanInstalled(); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	scan()
	scan()
	if n := strings.Count(logs.String(), "skip io.test.broken:"); n != 1 {
		t.Fatalf("logged %d times over 3 scans, want once:\n%s", n, logs.String())
	}
	if err := os.WriteFile(mf, []byte(`{"id": 7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	scan()
	scan()
	if n := strings.Count(logs.String(), "skip io.test.broken:"); n != 2 {
		t.Fatalf("logged %d times after the reason changed, want 2:\n%s", n, logs.String())
	}
}

// With Config.Slog set the messages carry a level: routine ones INFO,
// problems WARN, so a reader of the daemon's log (the Mac app counts the
// level-less lines as warnings) tells them apart.
func TestSlogCarriesTheLevel(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "io.pilot.wallet"), 0o700); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(root, "io.test.broken", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(mf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mf, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sl := slog.New(slog.NewTextHandler(&out, nil))
	var std bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub, Slog: sl}, Deps{}, log.New(&std, "", 0))
	if _, err := sup.scanInstalled(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `level=INFO msg="appstore: skip io.pilot.wallet: no manifest.json`) {
		t.Errorf("no-manifest skip not logged at INFO through slog:\n%s", got)
	}
	if !strings.Contains(got, `level=WARN msg="appstore: skip io.test.broken: parse:`) {
		t.Errorf("unparseable manifest not logged at WARN through slog:\n%s", got)
	}
	if std.Len() != 0 {
		t.Errorf("with Slog set, the log.Logger still got:\n%s", std.String())
	}
}

// pilotctl's install swaps a new dir in under the same path, which takes the
// running app's socket with it. That is a reinstall, logged as one (INFO) and
// marked so the supervise loop does not count the exit as a crash; a socket
// that vanishes from the same dir is still a warning.
func TestWatchSocketTellsAReinstallFromALostSocket(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "io.test.reap")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := fakeApp(dir, "/opt/pilot/apps/io.test.reap/bin/reap-app", "")
	cmd := startFakeApp(t, a.BinaryPath, "--socket", a.SocketPath)
	if err := os.WriteFile(a.SocketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s := newSupervisor(Config{}, Deps{}, log.New(&logs, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watched := make(chan struct{})
	go func() { s.watchSocket(ctx, a, cmd.Process.Pid, 20*time.Millisecond); close(watched) }()
	time.Sleep(100 * time.Millisecond) // let the watcher see the socket

	// The swap: the live dir moves aside, a fresh one takes its path.
	if err := os.Rename(dir, dir+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !waitExited(cmd, 5*time.Second) {
		t.Fatal("app kept running after it was reinstalled")
	}
	<-watched // its log and mark are written before it returns
	if !strings.Contains(logs.String(), "reinstalled while running") || strings.Contains(logs.String(), "vanished") {
		t.Fatalf("want the reinstall line, not the lost-socket warning:\n%s", logs.String())
	}
	if !s.takeReinstalled("io.test.reap") {
		t.Fatal("the reinstall was not marked: its exit would count as a crash")
	}
}

// A refused downgrade stays on disk, so every rescan finds it: it is logged
// (and audited) once, not every tick.
func TestRescanLogsARefusedDowngradeOnce(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.app"
	sha := strings.Repeat("a", 64)
	writeAppDirWithVersionSHA(t, root, id, "1.0.0", sha)
	var logs bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub, RescanInterval: time.Hour}, Deps{}, log.New(&logs, "", 0))
	newer := &installedApp{Dir: filepath.Join(root, id), Manifest: parseDummyManifest(t, id)}
	newer.Manifest.AppVersion = "2.0.0"
	sup.mu.Lock()
	sup.installed[id] = newer
	sup.mu.Unlock()
	for i := 0; i < 5; i++ {
		sup.rescanForNew()
	}
	if n := strings.Count(logs.String(), "downgrade refused"); n != 1 {
		t.Fatalf("logged %d times over 5 rescans, want once:\n%s", n, logs.String())
	}
}

// Uninstall deletes the app's dir; the supervise goroutine's last audit
// lines then have nowhere to go. That is the uninstall, not a problem.
func TestAuditLineForAnUninstalledAppIsSilent(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	sup := newSupervisor(Config{}, Deps{}, log.New(&logs, "", 0))
	a := fakeApp(filepath.Join(t.TempDir(), "gone"), "/bin/true", "")
	sup.writeAuditLine(a, auditEvent{Event: "exit"})
	if logs.Len() != 0 {
		t.Fatalf("audit write into a removed dir logged:\n%s", logs.String())
	}
}

// A manifest.json that is a dangling symlink is not "no manifest": it is a
// broken install, a warning.
func TestScanInstalled_DanglingManifestSymlinkIsAWarning(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "io.test.link")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "nowhere.json"), filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub, Slog: slog.New(slog.NewTextHandler(&out, nil))}, Deps{}, log.New(io.Discard, "", 0))
	if _, err := sup.scanInstalled(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `level=WARN msg="appstore: skip io.test.link: read manifest:`) {
		t.Fatalf("dangling manifest symlink not a read-manifest warning:\n%s", out.String())
	}
}
