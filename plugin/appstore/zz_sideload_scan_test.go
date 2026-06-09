// Sideload scan-time behaviour: presence of .sideloaded skips the
// publisher-signature check but applies the manifest allow-list. A
// manifest that satisfies the allow-list registers; one that doesn't
// is dropped, even if .sideloaded is present.

package appstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// sideloadOKManifestBody returns a manifest JSON that passes the
// sideload allow-list. Signature is a placeholder — the whole point
// is that .sideloaded makes the supervisor skip signature check.
const sideloadOKManifestBody = `{
	"id": "io.sideload.ok",
	"manifest_version": 1,
	"app_version": "0.1.0",
	"protection": "shareable",
	"binary": {"runtime": "go", "path": "bin/app", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	"exposes": ["sideload.ping"],
	"grants": [
		{"cap": "fs.read",  "target": "$APP/data.db"},
		{"cap": "fs.write", "target": "$APP/data.db"},
		{"cap": "audit.log", "target": "*"}
	],
	"store": {"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "signature": "sig:placeholder-unsigned"}
}`

func TestScanInstalled_SideloadedSkipsSignatureWhenPolicyOK(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	appDir := filepath.Join(root, "io.sideload.ok")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(sideloadOKManifestBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, manifest.SideloadMarkerName), nil, 0o400); err != nil {
		t.Fatal(err)
	}

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("apps = %d, want 1 (sideload should accept unsigned manifest)", len(apps))
	}
	if !apps[0].Sideloaded {
		t.Errorf("Sideloaded = false, want true")
	}
	if apps[0].Manifest.ID != "io.sideload.ok" {
		t.Errorf("ID = %q, want io.sideload.ok", apps[0].Manifest.ID)
	}
}

func TestScanInstalled_SideloadedRejectsWiderGrants(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	appDir := filepath.Join(root, "io.sideload.bad")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Same shape, but adds net.dial — outside the sideload allow-list.
	// Even with .sideloaded, scanInstalled must drop this app.
	body := `{
		"id": "io.sideload.bad",
		"manifest_version": 1,
		"app_version": "0.1.0",
		"protection": "shareable",
		"binary": {"runtime": "go", "path": "bin/app", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"exposes": ["sideload.bad"],
		"grants": [
			{"cap": "fs.read",  "target": "$APP/data.db"},
			{"cap": "net.dial", "target": "*.evil.com"}
		],
		"store": {"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "signature": "sig:placeholder"}
	}`
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, manifest.SideloadMarkerName), nil, 0o400); err != nil {
		t.Fatal(err)
	}

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (sideload policy must refuse net.dial)", len(apps))
	}
}

func TestScanInstalled_UnsignedWithoutMarkerStillRejected(t *testing.T) {
	t.Parallel()
	// Same manifest as the OK case but no `.sideloaded` file: this
	// must hit the regular signature path and be rejected, otherwise
	// the catalogue-vs-sideload trust line has been erased.
	root := t.TempDir()
	appDir := filepath.Join(root, "io.sideload.ok")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(sideloadOKManifestBody), 0o644); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT plant .sideloaded.

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (unsigned manifest without sideload marker must be refused)", len(apps))
	}
}
