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

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
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

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
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

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (unsigned manifest without sideload marker must be refused)", len(apps))
	}
}

// TestScanInstalled_UntrustedPublisherWithoutMarkerRejected is the
// trust-boundary regression: a manifest whose self-signature VERIFIES but
// whose publisher does NOT match the key the signed catalogue pins for the
// app, with no `.sideloaded` marker, must be refused. Signature validity
// alone is not trust — without the anchor, a self-signed-by-anyone manifest
// dropped into the install root would be accepted and spawned. Here the
// catalogue pins the fixed test key (testCatPub) but the app is signed by a
// fresh key, so VerifyTrustAnchor rejects the publisher/pin mismatch.
func TestScanInstalled_UntrustedPublisherWithoutMarkerRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Valid self-signature, fresh key that the catalogue does NOT pin, NO marker.
	writeUntrustedSignedAppDir(t, root, "io.untrusted.app")

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (publisher not matching the catalogue pin must be refused)", len(apps))
	}
}

// TestScanInstalled_CataloguePinnedAppAccepted is the positive case: an app
// signed by the key the catalogue pins for its id, with no sideload marker,
// passes VerifySignature + VerifyTrustAnchor and is accepted on the catalogue
// path (not marked sideloaded).
func TestScanInstalled_CataloguePinnedAppAccepted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeValidAppDir(t, root, "io.pinned.app") // signed by the test key, which testCatPub pins

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: testCatPub}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("apps = %d, want 1 (catalogue-pinned app must be accepted)", len(apps))
	}
	if apps[0].Sideloaded {
		t.Error("catalogue-pinned app must not be marked sideloaded")
	}
}

// TestScanInstalled_AppNotPinnedByCatalogueRejected proves the fail-closed
// property for the *pin presence*: an app whose self-signature is valid AND
// signed by the test key, but which the catalogue does NOT list (pinned=false),
// must be refused. Only apps the release-signed catalogue vouches for may run.
func TestScanInstalled_AppNotPinnedByCatalogueRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeValidAppDir(t, root, "io.unpinned.app") // validly signed by the test key
	notPinned := func(string) (string, bool) { return "", false }

	sup := newSupervisor(Config{InstallRoot: root, CataloguePublisher: notPinned}, Deps{}, newQuietLogger(t))
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (an app not pinned by the signed catalogue must be refused)", len(apps))
	}
}

// TestScanInstalled_NilCataloguePublisherFailsClosed guards the production
// default: if the daemon never wires a CataloguePublisher (nil), the supervisor
// cannot anchor any catalogue app, so non-sideloaded apps are refused rather
// than silently spawned unanchored.
func TestScanInstalled_NilCataloguePublisherFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeValidAppDir(t, root, "io.app")

	sup := newSupervisor(Config{InstallRoot: root}, Deps{}, newQuietLogger(t)) // CataloguePublisher nil
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Fatalf("apps = %d, want 0 (nil CataloguePublisher must fail closed)", len(apps))
	}
}
