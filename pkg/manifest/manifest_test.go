package manifest

import (
	"strings"
	"testing"
)

const validWalletManifest = `{
  "id": "io.pilot.wallet",
  "app_version": "0.1.0",
  "manifest_version": 1,
  "binary": {
    "runtime": "go",
    "path": "bin/wallet",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "exposes": ["wallet.balance", "wallet.pay", "wallet.request", "wallet.verify"],
  "grants": [
    {"cap": "fs.write", "target": "$APP/data.db"},
    {"cap": "net.dial", "target": "*.pilot",
     "if": {"kind": "rate", "params": {"per": "min", "limit": 100}}},
    {"cap": "key.sign", "target": "x402-auth",
     "if": {"kind": "cap", "params": {"asset": "USDC", "per": "day", "limit": 5}}}
  ],
  "protection": "guarded",
  "store": {
    "publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "signature": "sig:placeholder"
  },
  "affiliates": [
    {"pubkey": "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
     "role": "settlement", "purpose": "x402 settlement notary"}
  ]
}`

func TestValidWalletManifest(t *testing.T) {
	m, err := Parse([]byte(validWalletManifest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if errs := m.Validate(); len(errs) != 0 {
		for _, e := range errs {
			t.Errorf("unexpected: %v", e)
		}
	}
	if m.ID != "io.pilot.wallet" {
		t.Errorf("id mismatch: %q", m.ID)
	}
	if m.ManifestVersion != 1 {
		t.Errorf("manifest_version: %d", m.ManifestVersion)
	}
	if got, want := len(m.Grants), 3; got != want {
		t.Errorf("grants len: %d, want %d", got, want)
	}
}

func TestRejectsBadID(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"no_dot":        "wallet",
		"uppercase":     "io.Pilot.Wallet",
		"trailing_dot":  "io.pilot.wallet.",
	}
	for name, badID := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustValid(t)
			m.ID = badID
			errs := m.Validate()
			if !hasErrorContaining(errs, "id ") {
				t.Errorf("expected id error for %q, got: %v", badID, errs)
			}
		})
	}
}

func TestRejectsBadSemver(t *testing.T) {
	m := mustValid(t)
	m.AppVersion = "1.0"
	errs := m.Validate()
	if !hasErrorContaining(errs, "app_version") {
		t.Errorf("expected app_version error, got: %v", errs)
	}
}

func TestRejectsBadManifestVersion(t *testing.T) {
	m := mustValid(t)
	m.ManifestVersion = 0
	errs := m.Validate()
	if !hasErrorContaining(errs, "manifest_version") {
		t.Errorf("expected manifest_version error, got: %v", errs)
	}
}

func TestRejectsBadSHA256(t *testing.T) {
	cases := map[string]string{
		"too_short": "abc",
		"uppercase": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		"non_hex":   "zzzzzzzz" + "00000000000000000000000000000000000000000000000000000000",
		"empty":     "",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustValid(t)
			m.Binary.SHA256 = bad
			errs := m.Validate()
			if !hasErrorContaining(errs, "sha256") {
				t.Errorf("expected sha256 error, got: %v", errs)
			}
		})
	}
}

func TestRejectsUnknownCap(t *testing.T) {
	m := mustValid(t)
	m.Grants[0].Cap = "wat.unknown"
	errs := m.Validate()
	if !hasErrorContaining(errs, "wat.unknown") {
		t.Errorf("expected unknown-cap error, got: %v", errs)
	}
}

func TestRejectsUnknownRuntime(t *testing.T) {
	m := mustValid(t)
	m.Binary.Runtime = "haskell"
	errs := m.Validate()
	if !hasErrorContaining(errs, "runtime") {
		t.Errorf("expected runtime error, got: %v", errs)
	}
}

func TestRejectsMissingGrants(t *testing.T) {
	m := mustValid(t)
	m.Grants = nil
	errs := m.Validate()
	if !hasErrorContaining(errs, "at least one grant") {
		t.Errorf("expected missing-grants error, got: %v", errs)
	}
}

func TestRejectsBadProtection(t *testing.T) {
	m := mustValid(t)
	m.Protection = "encrypted"
	errs := m.Validate()
	if !hasErrorContaining(errs, "protection") {
		t.Errorf("expected protection error, got: %v", errs)
	}
}

func TestRejectsBadConditionKind(t *testing.T) {
	m := mustValid(t)
	m.Grants[1].Condition.Kind = "vibe"
	errs := m.Validate()
	if !hasErrorContaining(errs, "vibe") {
		t.Errorf("expected condition-kind error, got: %v", errs)
	}
}

func TestRejectsConditionBothLeafAndComposite(t *testing.T) {
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{
		Kind: "rate", Params: map[string]interface{}{"limit": 100},
		Op: "and", Compose: []Condition{{Kind: "rate"}},
	}
	errs := m.Validate()
	if !hasErrorContaining(errs, "both leaf") {
		t.Errorf("expected both-leaf-and-composite error, got: %v", errs)
	}
}

func TestCompositeConditionValid(t *testing.T) {
	m := mustValid(t)
	m.Grants[2].Condition = &Condition{
		Op: "and",
		Compose: []Condition{
			{Kind: "cap", Params: map[string]interface{}{"asset": "USDC", "per": "day", "limit": 5}},
			{Kind: "allowlist", Params: map[string]interface{}{"targets": []string{"*.pilot"}}},
		},
	}
	errs := m.Validate()
	for _, e := range errs {
		if strings.Contains(e.Error(), "grants[2].if") {
			t.Errorf("unexpected: %v", e)
		}
	}
}

func TestAcceptsExtendsBlock(t *testing.T) {
	m := mustValid(t)
	m.Exposes = append(m.Exposes, "wallet.hookPreSendMessage")
	m.Extends = []Extension{
		{
			Primitive: "send-message.pre",
			Method:    "wallet.hookPreSendMessage",
			AddsFlags: []FlagSpec{{Name: "--paywall", Type: "string", Help: "lock body behind payment"}},
		},
	}
	if errs := m.Validate(); len(errs) != 0 {
		for _, e := range errs {
			t.Errorf("unexpected: %v", e)
		}
	}
}

func TestRejectsMalformedHookPoint(t *testing.T) {
	m := mustValid(t)
	m.Exposes = append(m.Exposes, "wallet.h")
	m.Extends = []Extension{{Primitive: "bogus-no-phase", Method: "wallet.h"}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "<command>.<pre|post>") {
		t.Errorf("want malformed-hook-point error, got: %v", errs)
	}
}

func TestAcceptsDynamicExtends(t *testing.T) {
	m := mustValid(t)
	m.DynamicExtends = []string{"wallet.pay.pre", "send-message.post", "appstore.install.post"}
	if errs := m.Validate(); len(errs) != 0 {
		for _, e := range errs {
			t.Errorf("unexpected: %v", e)
		}
	}
}

func TestRejectsMalformedDynamicExtends(t *testing.T) {
	m := mustValid(t)
	m.DynamicExtends = []string{"valid.pre", "bogus-no-phase"}
	errs := m.Validate()
	if !hasErrorContaining(errs, "<command>.<pre|post>") {
		t.Errorf("want dynamic_extends malformed error, got %v", errs)
	}
}

func TestEmptyDynamicExtendsIsValid(t *testing.T) {
	m := mustValid(t)
	m.DynamicExtends = nil
	if errs := m.Validate(); len(errs) != 0 {
		t.Errorf("nil dynamic_extends should validate, got %v", errs)
	}
}

func TestAcceptsOpenCommandSpace(t *testing.T) {
	// Hook points against app-defined commands (wallet.pay.pre,
	// memories.recall.post) and pilotctl subcommands (appstore.install.pre)
	// must all validate — the namespace is open.
	for _, p := range []string{
		"wallet.pay.pre",
		"memories.recall.post",
		"appstore.install.pre",
		"some-other-thing.future.post",
	} {
		m := mustValid(t)
		m.Exposes = append(m.Exposes, "wallet.h")
		m.Extends = []Extension{{Primitive: p, Method: "wallet.h"}}
		if errs := m.Validate(); len(errs) != 0 {
			t.Errorf("hook %q rejected: %v", p, errs)
		}
	}
}

func TestRejectsExtendMethodNotInExposes(t *testing.T) {
	m := mustValid(t)
	// exposes is non-empty (from the canonical manifest); reference a
	// method that's missing from it.
	m.Extends = []Extension{{Primitive: "send-message.pre", Method: "wallet.notDeclared"}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "must appear in exposes") {
		t.Errorf("want method-not-in-exposes error, got: %v", errs)
	}
}

func TestRejectsBadFlagName(t *testing.T) {
	m := mustValid(t)
	m.Exposes = append(m.Exposes, "wallet.h")
	m.Extends = []Extension{{
		Primitive: "send-message.pre",
		Method:    "wallet.h",
		AddsFlags: []FlagSpec{{Name: "paywall", Type: "string"}},
	}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "must start with --") {
		t.Errorf("want flag-prefix error, got: %v", errs)
	}
}

func TestRejectsBadFlagType(t *testing.T) {
	m := mustValid(t)
	m.Exposes = append(m.Exposes, "wallet.h")
	m.Extends = []Extension{{
		Primitive: "send-message.pre",
		Method:    "wallet.h",
		AddsFlags: []FlagSpec{{Name: "--paywall", Type: "json"}},
	}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "string|bool|int") {
		t.Errorf("want flag-type error, got: %v", errs)
	}
}

func TestRejectsBadDependsApp(t *testing.T) {
	m := mustValid(t)
	m.Depends = []Dependency{{App: "wallet", Methods: []string{"pay"}}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "reverse-DNS") {
		t.Errorf("expected depends.app error, got: %v", errs)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

func mustValid(t *testing.T) *Manifest {
	t.Helper()
	m, err := Parse([]byte(validWalletManifest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func hasErrorContaining(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}
