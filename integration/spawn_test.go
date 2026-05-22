package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/plugin/appstore"
)

// walletSourceDir is the path to the wallet module relative to the dev
// layout. If absent (e.g. CI running on a checkout without sibling apps),
// spawn-tests t.Skip rather than fail.
const walletSourceDir = "/Users/calinteodor/Development/web4-apps/wallet"

// TestSupervisorSpawnsAndServesWallet builds the wallet binary, pins it
// into a fake install root with a real manifest, starts the supervisor
// through the daemon-shaped Adapter, dials the wallet over its socket,
// and asserts a real wallet.address call returns the expected pilot
// address. Then verifies clean shutdown.
func TestSupervisorSpawnsAndServesWallet(t *testing.T) {
	if _, err := os.Stat(walletSourceDir); err != nil {
		t.Skipf("wallet source not found at %s — skipping spawn integration", walletSourceDir)
	}

	// Unix sockets have a ~104-char path limit on macOS; t.TempDir() under
	// $TMPDIR can blow past that. Use a short /tmp prefix instead.
	installRoot, err := os.MkdirTemp("/tmp", "wspawn-")
	if err != nil {
		t.Fatalf("temp install root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(installRoot) })
	appDir := filepath.Join(installRoot, "io.pilot.wallet")
	binDir := filepath.Join(appDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	binaryPath := filepath.Join(binDir, "wallet")
	buildWalletBinary(t, walletSourceDir, binaryPath)

	sha, sErr := sha256File(binaryPath)
	if sErr != nil {
		t.Fatalf("sha256: %v", sErr)
	}

	manifestPath := filepath.Join(appDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(makeManifestJSON(sha)), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Start the adapter (daemon's eye view).
	svc := appstore.NewService(appstore.Config{InstallRoot: installRoot})
	adapter := New(svc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := adapter.Start(ctx, coreapi.Deps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := adapter.Stop(stopCtx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	// Poll for the wallet's unix socket to appear.
	sockPath := filepath.Join(appDir, "app.sock")
	waitForSocket(t, sockPath, 8*time.Second)

	// Make a real wallet.address call.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var resp struct {
		Address string `json:"address"`
	}
	if err := ipc.Call(conn, "wallet.address", nil, &resp); err != nil {
		t.Fatalf("wallet.address call: %v", err)
	}
	// The supervisor passes a sentinel address (daemonAddrFromDeps) until
	// we type-assert coreapi.Identity in tick 6+ work. Either way the
	// wallet should report *some* non-empty address.
	if resp.Address == "" {
		t.Errorf("wallet returned empty address")
	}
	t.Logf("wallet responded address=%q", resp.Address)
}

// buildWalletBinary runs `go build` against the wallet module's cmd/wallet
// and places the resulting binary at out. Fails the test on any error.
func buildWalletBinary(t *testing.T, srcDir, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "./cmd/wallet")
	cmd.Dir = srcDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build wallet: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("binary not at %s: %v", out, err)
	}
}

// sha256File returns the hex-encoded sha256 of a file's contents.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// waitForSocket polls until path exists and is a unix socket dialable,
// or fails the test on timeout.
func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear within %s", path, timeout)
}

// makeManifestJSON returns a valid io.pilot.wallet manifest with the
// supplied binary sha256. Mirrors examples/wallet.manifest.json plus the
// bin/wallet path used in the test layout.
func makeManifestJSON(binarySha256 string) string {
	return strings.NewReplacer("SHA", binarySha256).Replace(`{
  "id": "io.pilot.wallet",
  "app_version": "0.1.0",
  "manifest_version": 1,
  "binary": {
    "runtime": "go",
    "path": "bin/wallet",
    "sha256": "SHA"
  },
  "exposes": [
    "wallet.balance",
    "wallet.address",
    "wallet.pay",
    "wallet.request",
    "wallet.verify",
    "wallet.settle",
    "wallet.topup",
    "wallet.history"
  ],
  "grants": [
    {"cap": "fs.write", "target": "$APP/data.db"},
    {"cap": "fs.read",  "target": "$APP/data.db"},
    {"cap": "audit.log","target": "*"}
  ],
  "protection": "guarded",
  "store": {
    "publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "signature": "sig:placeholder-store-sig-for-integration-test"
  }
}`)
}
