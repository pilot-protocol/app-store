package appstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
// that passes manifest.Parse + Validate + VerifySignature (so scanInstalled
// accepts it). A fresh ed25519 keypair is generated per call so every
// test app has a self-consistent signature. No binary is written — the
// supervisor will hit verify-fail when it tries to spawn, but for tests
// that only care about discovery / registration (rescan, Apps()) that's
// the desired behavior.
func writeValidAppDir(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	template := strings.NewReplacer("ID", id, "PUBKEY", pubB64).Replace(`{
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
			"publisher": "ed25519:PUBKEY",
			"signature": ""
		}
	}`)

	// Parse, sign, re-serialize.
	m, err := manifest.Parse([]byte(template))
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	// Compute the signing payload the same way manifest.VerifySignature expects.
	grantsJSON, _ := json.Marshal(m.Grants)
	grantsHash := sha256.Sum256(grantsJSON)
	payload := fmt.Sprintf("%s:%s:%d:%s:%x",
		m.Store.Publisher, m.ID, m.ManifestVersion, m.Binary.SHA256, grantsHash)
	sig := ed25519.Sign(priv, []byte(payload))
	m.Store.Signature = base64.StdEncoding.EncodeToString(sig)

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal signed manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}
