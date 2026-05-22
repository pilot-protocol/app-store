package appstore

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// newQuietLogger returns a logger that discards output unless the test
// fails. Keeps `go test -v` readable.
func newQuietLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(io.Discard, "", 0)
}

// parseDummyManifest returns a minimal *manifest.Manifest with the
// given id. Used by tests that need a manifest struct without going
// through the disk layout. The values are intentionally minimal — the
// only purpose is to populate Apps() output.
func parseDummyManifest(t *testing.T, id string) *manifest.Manifest {
	t.Helper()
	return &manifest.Manifest{
		ID:              id,
		AppVersion:      "0.0.0",
		ManifestVersion: 1,
		Binary:          manifest.Binary{Runtime: "go", Path: "bin/x", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Protection:      "shareable",
	}
}

// writeValidAppDir creates <root>/<id>/manifest.json with a manifest
// that passes manifest.Parse + Validate (so scanInstalled accepts it).
// No binary is written — the supervisor will hit verify-fail when it
// tries to spawn, but for tests that only care about discovery /
// registration (rescan, Apps()) that's the desired behavior.
func writeValidAppDir(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	raw := strings.NewReplacer("ID", id).Replace(`{
		"id": "ID",
		"manifest_version": 1,
		"app_version": "0.0.0",
		"protection": "shareable",
		"binary": {"runtime": "go", "path": "bin/x", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"exposes": ["ID.method"],
		"grants": [
			{"cap": "fs.read", "target": "$APP/data.db"}
		],
		"store": {
			"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"signature": "sig:placeholder"
		}
	}`)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(raw), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}
