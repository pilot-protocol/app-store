package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/app-store/plugin/appstore"
)

// TestBrokerCallsThroughSupervisorIntoWallet exercises the layer that
// matters most for the integration: Service.Call → supervisor → spawned
// wallet → reply back. No direct socket dial, no short-cut. Proves the
// broker forwarding actually works end-to-end.
func TestBrokerCallsThroughSupervisorIntoWallet(t *testing.T) {
	if _, err := os.Stat(walletSourceDir); err != nil {
		t.Skipf("wallet source not found at %s — skipping broker spawn integration", walletSourceDir)
	}

	installRoot, err := os.MkdirTemp("/tmp", "broker-")
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
	buildWalletForBroker(t, walletSourceDir, binaryPath)

	sha, err := sha256ForBroker(binaryPath)
	if err != nil {
		t.Fatalf("sha256: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(makeManifestJSON(sha)), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Start the adapter / service.
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

	// Wait until Apps() reports the wallet as ready.
	deadline := time.Now().Add(8 * time.Second)
	for {
		apps := svc.Apps()
		ready := false
		for _, a := range apps {
			if a.ID == "io.pilot.wallet" && a.Ready {
				ready = true
				break
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wallet not reported ready within deadline; Apps=%+v", svc.Apps())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Call wallet.address through the broker (Service.Call), not the socket directly.
	var resp struct {
		Address string `json:"address"`
	}
	callCtx, callCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer callCancel()
	if err := svc.Call(callCtx, "io.pilot.wallet", "wallet.address", nil, &resp); err != nil {
		t.Fatalf("Service.Call: %v", err)
	}
	if resp.Address == "" {
		t.Errorf("empty address from broker")
	}
	t.Logf("broker dispatched wallet.address → %q", resp.Address)
}

// TestBrokerCallUnknownAppReturnsTypedError confirms the broker returns
// ErrAppNotInstalled (not a raw transport error) for unknown app ids.
func TestBrokerCallUnknownAppReturnsTypedError(t *testing.T) {
	installRoot := t.TempDir()
	svc := appstore.NewService(appstore.Config{InstallRoot: installRoot})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := svc.Start(ctx, appstore.Deps{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer svc.Stop(ctx)

	err := svc.Call(ctx, "no.such.app", "any.method", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown app")
	}
	// errors.Is would be ideal but Service.Call wraps; check for sentinel via substring.
	if got := err.Error(); !contains(got, "not installed") {
		t.Errorf("want 'not installed' error, got %v", err)
	}
}

func TestBrokerAppsListReflectsInstall(t *testing.T) {
	if _, err := os.Stat(walletSourceDir); err != nil {
		t.Skipf("wallet source not found at %s — skipping", walletSourceDir)
	}
	installRoot, _ := os.MkdirTemp("/tmp", "brkrlist-")
	t.Cleanup(func() { _ = os.RemoveAll(installRoot) })

	appDir := filepath.Join(installRoot, "io.pilot.wallet")
	binDir := filepath.Join(appDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	binaryPath := filepath.Join(binDir, "wallet")
	buildWalletForBroker(t, walletSourceDir, binaryPath)
	sha, _ := sha256ForBroker(binaryPath)
	_ = os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(makeManifestJSON(sha)), 0o644)

	svc := appstore.NewService(appstore.Config{InstallRoot: installRoot})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.Start(ctx, appstore.Deps{}); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop(ctx)

	apps := svc.Apps()
	if len(apps) != 1 {
		t.Fatalf("Apps(): %d, want 1", len(apps))
	}
	if apps[0].ID != "io.pilot.wallet" {
		t.Errorf("Apps()[0].ID = %q", apps[0].ID)
	}
	if apps[0].ManifestVersion < 1 {
		t.Errorf("manifest_version: %d", apps[0].ManifestVersion)
	}
	if len(apps[0].Methods) == 0 {
		t.Errorf("methods empty")
	}
}

// ── helpers (separate from spawn_test.go's helpers so tests can compile independently) ──

func buildWalletForBroker(t *testing.T, srcDir, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "./cmd/wallet")
	cmd.Dir = srcDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build wallet: %v", err)
	}
}

func sha256ForBroker(path string) (string, error) {
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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
