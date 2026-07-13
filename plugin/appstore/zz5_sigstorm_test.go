package appstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// writeBadSigAppDir creates <root>/<id>/manifest.json with a manifest
// that passes Parse + Validate but whose ed25519 signature does NOT
// verify: the payload is signed with a throwaway key that differs from
// the published publisher key. This is the exact shape that made
// scanInstalled log "signature verification failed" on every rescan
// tick. Returns the install-dir path.
func writeBadSigAppDir(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	// Published key (goes in the manifest) ...
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate publisher key: %v", err)
	}
	// ... but sign with a DIFFERENT key so verification fails.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
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
	sig := ed25519.Sign(wrongPriv, []byte(payload)) // wrong signer → fails verify
	m.Store.Signature = base64.StdEncoding.EncodeToString(sig)

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}

// bufLogger returns a logger writing into buf, for asserting on emitted lines.
func bufLogger(buf *bytes.Buffer) *log.Logger {
	return log.New(buf, "", 0)
}

// sigTestConfig returns a Config that pins the catalogue publisher to the
// fixed test key, so a writeValidAppDir manifest passes the FULL trust
// chain (signature + trust anchor) on the catalogue path.
func sigTestConfig(root string) Config {
	return Config{InstallRoot: root, CataloguePublisher: testCatPub}
}

// TestSignatureFailure_NoLogStorm reproduces the bug: an app whose
// manifest signature fails verification used to be re-scanned and
// re-logged on every rescan tick (683k identical lines observed). With
// dedup + backoff the identical failure must be logged exactly once no
// matter how many rescans fire.
func TestSignatureFailure_NoLogStorm(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBadSigAppDir(t, root, "io.bad.sig")

	var buf bytes.Buffer
	sup := newSupervisor(sigTestConfig(root), Deps{}, bufLogger(&buf))

	// Simulate 200 rescan ticks in a tight loop (the hot loop).
	const ticks = 200
	for i := 0; i < ticks; i++ {
		apps, err := sup.scanInstalled()
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		if len(apps) != 0 {
			t.Fatalf("scan %d returned %d apps; a bad-signature app must be skipped", i, len(apps))
		}
	}

	got := strings.Count(buf.String(), "manifest signature verification failed")
	if got != 1 {
		t.Fatalf("signature-failure logged %d times over %d rescans; want exactly 1 (dedup)", got, ticks)
	}

	// The app must be recorded as failing + throttled, not silently forgotten.
	sup.sigMu.Lock()
	rec, ok := sup.sigFails["io.bad.sig"]
	sup.sigMu.Unlock()
	if !ok {
		t.Fatal("expected a sigFails record for the bad app")
	}
	if rec.fails != 1 {
		// Only the first tick should have actually re-run VerifySignature;
		// the remaining ticks are throttled by the backoff timer.
		t.Fatalf("fails = %d; want 1 (subsequent ticks must be throttled, not re-verified)", rec.fails)
	}
	if sup.shouldAttemptSignature("io.bad.sig", rec.hash) {
		t.Fatal("app should be in backoff (shouldAttemptSignature=false) right after a failure")
	}
}

// TestSignatureFailure_BackoffGrowsAndQuarantines forces re-verification
// (by expiring the backoff timer each round) and asserts: retries are
// throttled via growing backoff, the app is quarantined after
// sigQuarantineAfter consecutive failures, and — crucially — the failure
// is STILL logged only once because the manifest hash never changed.
func TestSignatureFailure_BackoffGrowsAndQuarantines(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBadSigAppDir(t, root, "io.bad.sig")

	var buf bytes.Buffer
	sup := newSupervisor(sigTestConfig(root), Deps{}, bufLogger(&buf))

	var lastBackoff time.Duration
	for i := 0; i < sigQuarantineAfter+3; i++ {
		if _, err := sup.scanInstalled(); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		// Expire the backoff timer so the NEXT scan actually re-verifies.
		sup.sigMu.Lock()
		rec := sup.sigFails["io.bad.sig"]
		if rec != nil {
			if i > 0 && rec.backoff < lastBackoff {
				t.Fatalf("backoff shrank at round %d: %s < %s", i, rec.backoff, lastBackoff)
			}
			lastBackoff = rec.backoff
			rec.nextRetry = time.Now().Add(-time.Second)
		}
		sup.sigMu.Unlock()
	}

	sup.sigMu.Lock()
	rec := sup.sigFails["io.bad.sig"]
	sup.sigMu.Unlock()
	if rec == nil {
		t.Fatal("missing sigFails record")
	}
	if !rec.quarantined {
		t.Fatalf("app not quarantined after %d failures", rec.fails)
	}
	if rec.backoff <= sigBackoffStart {
		t.Fatalf("backoff did not grow: %s", rec.backoff)
	}
	if got := strings.Count(buf.String(), "manifest signature verification failed"); got != 1 {
		t.Fatalf("failure logged %d times; want 1 even across many retries (same hash)", got)
	}
	if got := strings.Count(buf.String(), "quarantined after"); got != 1 {
		t.Fatalf("quarantine logged %d times; want exactly 1", got)
	}
}

// TestSignatureFailure_ChangedManifestReLogs asserts a NEW/changed
// manifest (different content hash) escapes the dedup: it re-attempts
// verification and re-logs, so a genuinely different bad manifest isn't
// masked by a previous one's quarantine.
func TestSignatureFailure_ChangedManifestReLogs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBadSigAppDir(t, root, "io.bad.sig")

	var buf bytes.Buffer
	sup := newSupervisor(sigTestConfig(root), Deps{}, bufLogger(&buf))

	if _, err := sup.scanInstalled(); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	// Rewrite the app with a fresh (still-bad) manifest → new content hash.
	writeBadSigAppDir(t, root, "io.bad.sig")
	if _, err := sup.scanInstalled(); err != nil {
		t.Fatalf("scan 2: %v", err)
	}

	if got := strings.Count(buf.String(), "manifest signature verification failed"); got != 2 {
		t.Fatalf("changed manifest logged %d times; want 2 (a new hash must re-log)", got)
	}
}

// TestSignatureFailure_RecoveryClearsQuarantine asserts that once the
// full trust chain verifies (operator re-installs a properly signed,
// catalogue-pinned manifest), the quarantine state is cleared, a recovery
// line is emitted, and the app is admitted by scanInstalled.
func TestSignatureFailure_RecoveryClearsQuarantine(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBadSigAppDir(t, root, "io.fix.me")

	var buf bytes.Buffer
	sup := newSupervisor(sigTestConfig(root), Deps{}, bufLogger(&buf))

	if apps, err := sup.scanInstalled(); err != nil || len(apps) != 0 {
		t.Fatalf("initial scan: apps=%d err=%v; want 0 apps skipped", len(apps), err)
	}
	sup.sigMu.Lock()
	_, failing := sup.sigFails["io.fix.me"]
	sup.sigMu.Unlock()
	if !failing {
		t.Fatal("expected failure record before recovery")
	}

	// Operator re-installs with a valid, catalogue-pinned signature.
	writeValidAppDir(t, root, "io.fix.me")
	apps, err := sup.scanInstalled()
	if err != nil {
		t.Fatalf("recovery scan: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("recovery scan returned %d apps; want 1 (now admitted)", len(apps))
	}
	sup.sigMu.Lock()
	_, stillFailing := sup.sigFails["io.fix.me"]
	sup.sigMu.Unlock()
	if stillFailing {
		t.Fatal("quarantine state not cleared after a successful verify")
	}
	if !strings.Contains(buf.String(), "signature now verifies") {
		t.Fatal("expected a recovery log line")
	}
}

// TestTrustAnchorFailure_NoLogStorm covers the OTHER catalogue failure
// mode: a manifest with a valid self-signature but an untrusted publisher
// (fails VerifyTrustAnchor). It is skipped and re-examined every tick just
// like a bad signature, so it must also be deduped to a single log line.
func TestTrustAnchorFailure_NoLogStorm(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeUntrustedSignedAppDir(t, root, "io.untrusted.pub")

	var buf bytes.Buffer
	sup := newSupervisor(sigTestConfig(root), Deps{}, bufLogger(&buf))

	for i := 0; i < 100; i++ {
		apps, err := sup.scanInstalled()
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		if len(apps) != 0 {
			t.Fatalf("scan %d returned %d apps; an untrusted-publisher app must be skipped", i, len(apps))
		}
	}
	if got := strings.Count(buf.String(), "manifest signature verification failed"); got != 1 {
		t.Fatalf("trust-anchor failure logged %d times over 100 rescans; want exactly 1 (dedup)", got)
	}
}
