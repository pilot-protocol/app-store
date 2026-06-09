package manifest

import (
	"strings"
	"testing"
)

// baseSideloadOK returns a manifest that satisfies EnforceSideloadPolicy.
// Each test mutates exactly one field, asserts the error message names
// the violation, then restores the field. Drift in any constraint
// surfaces as a single failing assertion instead of a wall of red.
func baseSideloadOK() *Manifest {
	return &Manifest{
		ID:              "io.example.hello",
		AppVersion:      "0.1.0",
		ManifestVersion: 1,
		Binary: Binary{
			Runtime: "go",
			Path:    "bin/hello",
			SHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Grants: []Grant{
			{Cap: "fs.read", Target: "$APP/config.json"},
			{Cap: "fs.write", Target: "$APP/data.db"},
			{Cap: "audit.log", Target: "*"},
		},
		Store: Store{
			Publisher: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Signature: "sig:placeholder",
		},
	}
}

func TestEnforceSideloadPolicy_AllowsBaseline(t *testing.T) {
	if err := EnforceSideloadPolicy(baseSideloadOK()); err != nil {
		t.Fatalf("baseline manifest must satisfy policy, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsNilManifest(t *testing.T) {
	if err := EnforceSideloadPolicy(nil); err == nil {
		t.Fatal("nil manifest must fail policy")
	}
}

func TestEnforceSideloadPolicy_RejectsGuardedProtection(t *testing.T) {
	m := baseSideloadOK()
	m.Protection = "guarded"
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "guarded") {
		t.Fatalf("guarded protection must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsExtends(t *testing.T) {
	m := baseSideloadOK()
	m.Extends = []Extension{{Primitive: "send-message.pre", Method: "x.y"}}
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "extends") {
		t.Fatalf("extends must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsDynamicExtends(t *testing.T) {
	m := baseSideloadOK()
	m.DynamicExtends = []string{"some.hook"}
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "dynamic_extends") {
		t.Fatalf("dynamic_extends must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsAffiliates(t *testing.T) {
	m := baseSideloadOK()
	m.Affiliates = []Affiliate{{Pubkey: "ed25519:zzzz", Role: "settlement"}}
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "affiliates") {
		t.Fatalf("affiliates must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsDepends(t *testing.T) {
	m := baseSideloadOK()
	m.Depends = []Dependency{{App: "io.pilot.wallet"}}
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "depends") {
		t.Fatalf("depends must be refused (cross-app IPC), got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsNetDial(t *testing.T) {
	m := baseSideloadOK()
	m.Grants = append(m.Grants, Grant{Cap: "net.dial", Target: "*.example.com"})
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "net.dial") {
		t.Fatalf("net.dial must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsKeySign(t *testing.T) {
	m := baseSideloadOK()
	m.Grants = append(m.Grants, Grant{Cap: "key.sign", Target: "x402-auth"})
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "key.sign") {
		t.Fatalf("key.sign must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsIPCCallToOtherApps(t *testing.T) {
	m := baseSideloadOK()
	m.Grants = append(m.Grants, Grant{Cap: "ipc.call", Target: "io.pilot.wallet.evm.satisfy"})
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "ipc.call") {
		t.Fatalf("ipc.call must be refused (no cross-app calls), got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsFSPathOutsideAPP(t *testing.T) {
	cases := []struct {
		name, target string
	}{
		{"absolute /etc", "/etc/passwd"},
		{"home dir", "$HOME/.ssh"},
		{"parent escape", "$APP/../../etc/passwd"},
		{"bare app", "$APP/"},
		{"no app prefix", "bin/data"},
		{"empty", ""},
		{"app then absolute", "$APP//etc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := baseSideloadOK()
			m.Grants[0].Target = tc.target
			err := EnforceSideloadPolicy(m)
			if err == nil {
				t.Fatalf("target %q must be refused (outside $APP)", tc.target)
			}
		})
	}
}

func TestEnforceSideloadPolicy_RejectsConditionalGrant(t *testing.T) {
	m := baseSideloadOK()
	m.Grants[0].Condition = &Condition{Kind: "rate", Params: map[string]interface{}{"per": "min", "limit": 60}}
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "unconditional") {
		t.Fatalf("conditional grant must be refused, got: %v", err)
	}
}

func TestEnforceSideloadPolicy_RejectsUnknownCap(t *testing.T) {
	m := baseSideloadOK()
	m.Grants = append(m.Grants, Grant{Cap: "wat.future", Target: "$APP/data"})
	err := EnforceSideloadPolicy(m)
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("unknown cap must be refused, got: %v", err)
	}
}

func TestSideloadAllowedCaps_Closed(t *testing.T) {
	// The allow-list is the security boundary. Any change to its
	// contents must be a deliberate, reviewable edit — this test
	// makes the membership explicit so a typo or accidental addition
	// fails CI rather than slipping into prod.
	want := map[string]struct{}{"audit.log": {}, "fs.read": {}, "fs.write": {}}
	if len(SideloadAllowedCaps) != len(want) {
		t.Fatalf("allow-list size changed: want %d entries, got %d (%v)",
			len(want), len(SideloadAllowedCaps), SideloadAllowedCaps)
	}
	for k := range want {
		if _, ok := SideloadAllowedCaps[k]; !ok {
			t.Errorf("expected cap %q in allow-list", k)
		}
	}
}
