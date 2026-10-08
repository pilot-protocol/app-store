package appstore

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAppDirAt writes an app dir for id (writeAppDirWithVersionSHA, in a
// scratch root) and moves it to <root>/<dirName>: an install-root entry that
// holds a valid manifest for id under a name that is not id, like pilotctl's
// <id>.staging and <id>.previous.
func writeAppDirAt(t *testing.T, root, dirName, id, version, binSHA string) string {
	t.Helper()
	src := writeAppDirWithVersionSHA(t, t.TempDir(), id, version, binSHA)
	dst := filepath.Join(root, dirName)
	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestRescanIgnoresStagingAndPreviousDirs: pilotctl's install leaves
// <id>.staging (from the manifest write to the swap) and <id>.previous (from
// the swap until it is retired) beside the live <id>, each holding a valid
// manifest for the app. scanInstalled adopted both, so on a same-version
// rebuild the rescan swapped the new <id> in and then "rebuilt" the app again
// from .previous and .staging: several supervise goroutines for one app, each
// overwriting appCancel[id] and reaping the others' process, until the app
// was suspended. Only <id> may be adopted, and the next tick must be a no-op.
func TestRescanIgnoresStagingAndPreviousDirs(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.app"
	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	shaC := strings.Repeat("c", 64)
	live := writeAppDirWithVersionSHA(t, root, id, "1.0.0", shaB)
	writeAppDirAt(t, root, id+".previous", id, "1.0.0", shaA)
	writeAppDirAt(t, root, id+".staging", id, "1.0.0", shaC)

	sup := newSupervisor(Config{
		CataloguePublisher: testCatPub,
		InstallRoot:        root,
		RescanInterval:     20 * 1e6,
	}, Deps{}, newQuietLogger(t))

	// In memory: the install from before the rebuild (sha A).
	entry := &installedApp{
		Dir:        live,
		Manifest:   parseDummyManifest(t, id),
		BinaryPath: filepath.Join(live, "bin/x"),
	}
	entry.Manifest.AppVersion = "1.0.0"
	entry.Manifest.Binary.SHA256 = shaA
	sup.mu.Lock()
	sup.installed[id] = entry
	sup.mu.Unlock()

	fresh := sup.rescanForNew()
	var dirs []string
	for _, a := range fresh {
		dirs = append(dirs, filepath.Base(a.Dir))
	}
	if len(fresh) != 1 || fresh[0].Dir != live {
		t.Fatalf("rescanForNew started %v, want exactly [%s]", dirs, id)
	}
	sup.mu.RLock()
	got := sup.installed[id]
	sup.mu.RUnlock()
	if got.Dir != live || got.Manifest.Binary.SHA256 != shaB {
		t.Errorf("installed[%s] = %s pinned %s, want %s pinned %s",
			id, filepath.Base(got.Dir), shortSHA(got.Manifest.Binary.SHA256), id, shortSHA(shaB))
	}
	// Nothing changed on disk: the next tick must not restart the app again.
	if again := sup.rescanForNew(); len(again) != 0 {
		t.Errorf("unchanged install root restarted %d apps on the next tick, want 0", len(again))
	}
}

// TestScanInstalled_SkipsDirNotNamedForItsApp: only <InstallRoot>/<id> is an
// install. A dir holding a valid manifest under any other name (pilotctl's
// <id>.previous, a hand-made copy) is skipped. Daemon start runs every scanned
// dir, so adopting one ran a second copy of the app beside the live one. The
// skip is logged once per dir, not on every rescan, and again only if the dir
// goes away and comes back.
func TestScanInstalled_SkipsDirNotNamedForItsApp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const id = "io.test.app"
	sha := strings.Repeat("a", 64)
	live := writeAppDirWithVersionSHA(t, root, id, "1.0.0", sha)
	writeAppDirAt(t, root, id+".previous", id, "1.0.0", sha)
	copyDir := writeAppDirAt(t, root, "copy-of-test-app", id, "1.0.0", sha)

	var logs bytes.Buffer
	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, log.New(&logs, "", 0))
	scan := func() {
		t.Helper()
		apps, err := sup.scanInstalled()
		if err != nil {
			t.Fatal(err)
		}
		var dirs []string
		for _, a := range apps {
			dirs = append(dirs, filepath.Base(a.Dir))
		}
		if len(apps) != 1 || apps[0].Dir != live {
			t.Fatalf("scanInstalled adopted %v, want exactly [%s]", dirs, id)
		}
	}
	logged := func(name string) int {
		return strings.Count(logs.String(), "skip "+name+":")
	}

	for i := 0; i < 3; i++ {
		scan()
	}
	for _, name := range []string{id + ".previous", "copy-of-test-app"} {
		if n := logged(name); n != 1 {
			t.Errorf("%s logged %d times over 3 scans, want once:\n%s", name, n, logs.String())
		}
	}

	// Gone, then back: a new occurrence is logged again.
	if err := os.RemoveAll(copyDir); err != nil {
		t.Fatal(err)
	}
	scan()
	writeAppDirAt(t, root, "copy-of-test-app", id, "1.0.0", sha)
	scan()
	if n := logged("copy-of-test-app"); n != 2 {
		t.Errorf("copy-of-test-app logged %d times after it came back, want 2:\n%s", n, logs.String())
	}
}
