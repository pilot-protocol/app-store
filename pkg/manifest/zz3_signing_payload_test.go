package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// signedV2 returns a valid wallet manifest signed with the v2 payload.
func signedV2(t *testing.T) *Manifest {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := mustValid(t)
	m.Store.Publisher = "ed25519:" + base64Enc(pub)
	if _, err := m.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := m.VerifySignature(); err != nil {
		t.Fatalf("freshly signed manifest rejected: %v", err)
	}
	return m
}

// TestV2PayloadCoversWholeManifest walks every field that the v1 payload left
// outside the signed bytes and asserts that editing it now breaks verification.
func TestV2PayloadCoversWholeManifest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"binary.path", func(m *Manifest) { m.Binary.Path = "bin/other" }},
		{"binary.runtime", func(m *Manifest) { m.Binary.Runtime = "bun" }},
		{"binary.sha256", func(m *Manifest) {
			m.Binary.SHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"exposes", func(m *Manifest) { m.Exposes = append(m.Exposes, "wallet.drain") }},
		{"protection", func(m *Manifest) { m.Protection = "shareable" }},
		{"affiliates.pubkey", func(m *Manifest) { m.Affiliates[0].Pubkey = "ed25519:CCCC" }},
		{"affiliates.append", func(m *Manifest) {
			m.Affiliates = append(m.Affiliates, Affiliate{Pubkey: "ed25519:DDDD", Role: "settlement", Purpose: "extra"})
		}},
		{"depends", func(m *Manifest) {
			m.Depends = append(m.Depends, Dependency{App: "io.pilot.keyring", Methods: []string{"keyring.export"}})
		}},
		{"extends", func(m *Manifest) {
			m.Extends = append(m.Extends, Extension{Primitive: "send-message.pre", Method: "wallet.verify"})
		}},
		{"dynamic_extends", func(m *Manifest) {
			m.DynamicExtends = append(m.DynamicExtends, "send-message.pre")
		}},
		{"app_version", func(m *Manifest) { m.AppVersion = "9.9.9" }},
		{"id", func(m *Manifest) { m.ID = "io.pilot.other" }},
		{"manifest_version", func(m *Manifest) { m.ManifestVersion = 2 }},
		{"grants.cap", func(m *Manifest) { m.Grants[0].Cap = "proc.exec" }},
		{"grants.target", func(m *Manifest) { m.Grants[0].Target = "/etc/passwd" }},
		{"grants.condition", func(m *Manifest) { m.Grants[1].Condition = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := signedV2(t)
			tc.mutate(m)
			if err := m.VerifySignature(); err == nil {
				t.Errorf("expected verification failure after editing %s, got nil", tc.name)
			}
		})
	}
}

// TestV1SignatureStillVerifies pins the compatibility guarantee: manifests
// signed with the v1 payload keep verifying while the legacy fallback is on.
func TestV1SignatureStillVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := mustValid(t)
	m.Store.Publisher = "ed25519:" + base64Enc(pub)
	sig, err := signTestManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	m.Store.Signature = sig

	if !AllowLegacySignaturePayload {
		t.Fatal("AllowLegacySignaturePayload must default to true")
	}
	if err := m.VerifySignature(); err != nil {
		t.Errorf("v1 signature rejected with legacy fallback enabled: %v", err)
	}
}

// TestLegacyFallbackCanBeDisabled checks the toggle in both directions: with
// the fallback off, only v2 signatures verify.
func TestLegacyFallbackCanBeDisabled(t *testing.T) {
	prev := AllowLegacySignaturePayload
	t.Cleanup(func() { AllowLegacySignaturePayload = prev })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := mustValid(t)
	m.Store.Publisher = "ed25519:" + base64Enc(pub)
	v1Sig, err := signTestManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	m.Store.Signature = v1Sig

	AllowLegacySignaturePayload = false
	if err := m.VerifySignature(); err == nil {
		t.Error("expected v1 signature to be rejected with the legacy fallback disabled")
	}

	if _, err := m.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := m.VerifySignature(); err != nil {
		t.Errorf("v2 signature rejected with the legacy fallback disabled: %v", err)
	}
}

// TestV1PayloadLeavesFieldsUnsigned records the difference between the two
// payloads: a v1 signature does not move when Binary.Path changes, which is
// exactly the range v2 extends over.
func TestV1PayloadLeavesFieldsUnsigned(t *testing.T) {
	m := mustValid(t)
	m.Store.Publisher = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	before, err := m.signingPayloadV1()
	if err != nil {
		t.Fatal(err)
	}
	beforeV2, err := m.signingPayloadV2()
	if err != nil {
		t.Fatal(err)
	}

	m.Binary.Path = "bin/elsewhere"
	m.DynamicExtends = append(m.DynamicExtends, "recv.post")

	after, err := m.signingPayloadV1()
	if err != nil {
		t.Fatal(err)
	}
	afterV2, err := m.signingPayloadV2()
	if err != nil {
		t.Fatal(err)
	}

	if string(before) != string(after) {
		t.Errorf("v1 payload unexpectedly changed:\n%s\n%s", before, after)
	}
	if string(beforeV2) == string(afterV2) {
		t.Error("v2 payload did not change after editing binary.path and dynamic_extends")
	}
}

// TestSigningPayloadIndependentOfSignatureField confirms the payload is stable
// whether or not Store.Signature is populated, so signer and verifier agree.
func TestSigningPayloadIndependentOfSignatureField(t *testing.T) {
	m := mustValid(t)
	m.Store.Signature = ""
	unsigned, err := m.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	m.Store.Signature = "ed25519:AAAA"
	populated, err := m.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if string(unsigned) != string(populated) {
		t.Errorf("payload depends on store.signature:\n%s\n%s", unsigned, populated)
	}
	if m.Store.Signature != "ed25519:AAAA" {
		t.Errorf("SigningPayload mutated store.signature: %q", m.Store.Signature)
	}
}

func TestSignRejectsMismatchedPublisher(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := mustValid(t)
	m.Store.Publisher = "ed25519:" + base64Enc(otherPub)
	if _, err := m.Sign(priv); err == nil {
		t.Error("expected Sign to refuse a publisher that is not the signing key")
	}
}

// TestV2SignatureIsNotAcceptedForAnotherPublisher checks the publisher binding
// survives in v2: re-labelling the manifest with a different publisher key
// breaks the signature under both payload versions.
func TestV2SignatureIsNotAcceptedForAnotherPublisher(t *testing.T) {
	m := signedV2(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.Store.Publisher = "ed25519:" + base64Enc(otherPub)
	if err := m.VerifySignature(); err == nil {
		t.Error("expected verification failure after swapping store.publisher")
	}
}
