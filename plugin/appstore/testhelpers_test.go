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

// testPublisherSeed is a fixed Ed25519 seed so every helper-built
// manifest is signed by the SAME publisher key, and testCatPub pins that
// key as the catalogue publisher — so helper-built (catalogue) apps pass
// the trust anchor in supervisor tests.
var testPublisherSeed = [ed25519.SeedSize]byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

func testPublisherKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(testPublisherSeed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// testCatPub is a Config.CataloguePublisher that pins every app id to the fixed
// test publisher key. Wire it into a supervisor Config so a writeValidAppDir app
// (signed by that key) passes VerifyTrustAnchor on the catalogue path, while an
// app signed by any other key (writeUntrustedSignedAppDir) is rejected as a
// publisher/catalogue-pin mismatch.
func testCatPub(string) (string, bool) {
	pub, _ := testPublisherKey()
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub), true
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
// that passes manifest.Parse + Validate + VerifySignature AND
// VerifyTrustAnchor (so scanInstalled accepts it on the catalogue path).
// It signs with the fixed test publisher key that TestMain pins into
// manifest.TrustedPublishers. No binary is written — the supervisor
// will hit verify-fail when it tries to spawn, but for tests that only
// care about discovery / registration (rescan, Apps()) that's the
// desired behavior.
func writeValidAppDir(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	pub, priv := testPublisherKey()
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

// writeUntrustedSignedAppDir creates <root>/<id>/manifest.json with a
// manifest that carries a VALID self-signature from a FRESH (untrusted)
// publisher key — i.e. it passes VerifySignature but NOT VerifyTrustAnchor.
// No `.sideloaded` marker is planted. This is the trust-boundary case:
// a catalogue install must be refused unless the publisher is on the
// trusted-publishers list, even when the signature itself is internally
// consistent.
func writeUntrustedSignedAppDir(t *testing.T, root, id string) string {
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

	m, err := manifest.Parse([]byte(template))
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
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
