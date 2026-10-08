package appstore

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
