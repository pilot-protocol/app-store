// Package manifest defines the typed schema for a pilot app manifest.
//
// The manifest is the *only* source of truth for an app's grants — the runtime
// never infers permissions from anywhere else. Pinned at install time and
// re-verified on every launch.
//
// See ../docs/architecture/graph.json (node id: "manifest") for the canonical
// description; this file is the Go embodiment of that node.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Manifest is the signed declaration of what an app is and what it's allowed
// to do.
type Manifest struct {
	// Unique app identifier, reverse-DNS form (e.g. "io.pilot.wallet").
	ID string `json:"id"`

	// AppVersion is the publisher's semver — bumps freely on bug fixes and
	// feature work, applied as silent binary swaps.
	AppVersion string `json:"app_version"`

	// ManifestVersion is a monotonic int that increments ONLY when the grants
	// list, affiliates, or any other security-affecting field changes.
	// Same ManifestVersion ⇒ silent update; bumped ⇒ explicit re-consent.
	ManifestVersion int `json:"manifest_version"`

	Binary  Binary   `json:"binary"`
	Exposes []string `json:"exposes,omitempty"`
	Grants  []Grant  `json:"grants"`

	// Protection: "shareable" (default) or "guarded" (encrypted volume +
	// restricted process namespace).
	Protection string `json:"protection,omitempty"`

	Store Store `json:"store"`

	Affiliates []Affiliate  `json:"affiliates,omitempty"`
	Depends    []Dependency `json:"depends,omitempty"`

	// Extends is the set of daemon-primitive hook points this app
	// participates in. Each entry says: at this primitive (e.g.
	// "send-message.pre"), call my Method via IPC; the daemon's
	// extend.Registry threads HookArgs through the chain. AddsFlags
	// contribute to pilotctl's CLI surface for that primitive when
	// this app is installed.
	Extends []Extension `json:"extends,omitempty"`

	// DynamicExtends is the set of hook points this app may register
	// against at runtime via the daemon's extend.register IPC. Empty
	// (or absent) means no runtime registration is allowed. This is
	// the user-visible bound on dynamic behavior — the user reviews
	// this list at install/upgrade, same as Grants.
	DynamicExtends []string `json:"dynamic_extends,omitempty"`
}

// Binary identifies the executable and what it must hash to.
type Binary struct {
	// Runtime: "go" | "bun" | "node" | "python"
	Runtime string `json:"runtime"`
	Path    string `json:"path"`
	// SHA256 is the lowercase-hex sha256 of the binary at Path.
	SHA256 string `json:"sha256"`
}

// Grant is a (capability, target, condition?) triple. The runtime brokers
// every privileged op and grants are the only thing that authorizes them.
type Grant struct {
	// Cap: "fs.read" | "fs.write" | "net.dial" | "net.call" | "ipc.call" |
	//      "key.sign" | "audit.log" | ...
	Cap string `json:"cap"`

	// Target: path pattern, host pattern, "<app>.<method>", or sign-purpose.
	Target string `json:"target"`

	// Condition is optional. If absent, the grant is unconditional.
	Condition *Condition `json:"if,omitempty"`
}

// Condition is a predicate the daemon evaluates per request.
// Either Kind+Params (a leaf condition) OR Compose+Op (composite). Not both.
type Condition struct {
	// Leaf form:
	//   Kind: "rate" | "cap" | "allowlist" | "denylist" | "time_window" |
	//         "requires_user_consent" | "requires_foreground" | "signed_by"
	Kind   string                 `json:"kind,omitempty"`
	Params map[string]interface{} `json:"params,omitempty"`

	// Composite form:
	Op      string      `json:"op,omitempty"` // "and" | "or" | "not"
	Compose []Condition `json:"compose,omitempty"`
}

// Store: the signature-chain anchor.
type Store struct {
	// Publisher pubkey, base64 ed25519 ("ed25519:<base64>").
	Publisher string `json:"publisher"`
	// Signature: store's signature over (id || manifest_version || binary.sha256 || grants-hash).
	Signature string `json:"signature"`
}

// Affiliate: a pilot-network endpoint that's co-trusted with this app
// (e.g. wallet's settlement notary). Calls between the app and an affiliate
// pass through without per-call user consent.
type Affiliate struct {
	Pubkey  string `json:"pubkey"`
	Role    string `json:"role"`
	Purpose string `json:"purpose"`
}

// Dependency: the calling app declares which methods of which other apps it
// expects to invoke. User reviews these at install time.
type Dependency struct {
	App     string   `json:"app"`
	Methods []string `json:"methods"`
}

// Extension is one hook the app registers with the daemon's extend.Registry.
// The Primitive must be one of the runtime's known hook points (see
// pkg/extend KnownHookPoints — duplicated here as a small known-string set
// so pkg/manifest stays dep-free).
type Extension struct {
	// Primitive names the hook point, e.g. "send-message.pre" or "recv.post".
	Primitive string `json:"primitive"`

	// Method is the IPC method name the daemon dispatches to when this
	// hook fires. Must be present in the app's `exposes` list.
	Method string `json:"method"`

	// AddsFlags are CLI flags this hook contributes to pilotctl when the
	// app is installed. Optional.
	AddsFlags []FlagSpec `json:"adds_flags,omitempty"`

	// Order determines chain position when multiple apps hook the same
	// primitive. Lower runs earlier. Default 0.
	Order int `json:"order,omitempty"`
}

// FlagSpec describes one CLI flag an Extension contributes.
type FlagSpec struct {
	Name string `json:"name"` // "--paywall" — must start with "--"
	Type string `json:"type"` // "string" | "bool" | "int"
	Help string `json:"help,omitempty"`
}

// Parse decodes a manifest from JSON bytes. Does not validate; call Validate
// after Parse for the policy-level checks.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Marshal serializes the manifest as deterministic JSON (sorted keys).
// Use this for signing inputs — the signature must be over a canonical form.
func (m *Manifest) Marshal() ([]byte, error) {
	// json.Marshal sorts struct fields by declaration order; for canonical
	// output across implementations, we additionally sort map keys via the
	// standard library's behavior (it already sorts map[string]interface{}).
	return json.Marshal(m)
}

// canonicalJSON returns deterministic JSON bytes for v (sorted keys).
func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// signingPayload builds the canonical byte-string the Store.Signature
// must sign. The publisher key is included so that a signature cannot
// be reused with a different publisher identity — swapping the
// publisher key invalidates the signature. Once a trust-anchor check
// (hardcoded publisher pubkey match) is added, this guarantees the
// manifest was signed by the known publisher.
//
// Format: publisher || ":" || id || ":" || manifest_version || ":" || binary.sha256 || ":" || grants-sha256-hex
func (m *Manifest) signingPayload() ([]byte, error) {
	grantsJSON, err := canonicalJSON(m.Grants)
	if err != nil {
		return nil, fmt.Errorf("grants marshal: %w", err)
	}
	grantsHash := sha256.Sum256(grantsJSON)
	payload := fmt.Sprintf("%s:%s:%d:%s:%x",
		m.Store.Publisher, m.ID, m.ManifestVersion, m.Binary.SHA256, grantsHash)
	return []byte(payload), nil
}

// TrustedPublishers is the compile-time-embedded list of publisher
// ed25519 public keys ("ed25519:<base64>" or raw base64) that are
// trusted to sign manifests. Empty list = fail-closed (no publisher
// passes the trust-anchor check). Production builds MUST populate
// this list with the known-good publisher keys.
var TrustedPublishers []string

// VerifyTrustAnchor checks that Store.Publisher is on the trusted
// publishers list. Without this check, VerifySignature only confirms
// the manifest was signed by whoever claims to be the publisher;
// VerifyTrustAnchor confirms the publisher itself is known and trusted.
//
// Returns nil if Store.Publisher is in TrustedPublishers.
// Returns an error if TrustedPublishers is empty (fail-closed) or if
// the publisher is not found.
func (m *Manifest) VerifyTrustAnchor() error {
	if len(TrustedPublishers) == 0 {
		return fmt.Errorf("trust anchor: TrustedPublishers is empty — no publisher is trusted")
	}

	pubkeyRaw, ok := strings.CutPrefix(m.Store.Publisher, "ed25519:")
	if !ok {
		return fmt.Errorf("store.publisher must be \"ed25519:<base64>\"")
	}
	pubkey, err := base64.StdEncoding.DecodeString(pubkeyRaw)
	if err != nil {
		return fmt.Errorf("store.publisher: invalid base64: %w", err)
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("store.publisher: wrong key length %d, want %d", len(pubkey), ed25519.PublicKeySize)
	}

	for _, trusted := range TrustedPublishers {
		trustedRaw := strings.TrimPrefix(trusted, "ed25519:")
		trustedKey, err := base64.StdEncoding.DecodeString(trustedRaw)
		if err != nil {
			continue // skip malformed entries
		}
		if bytes.Equal(pubkey, trustedKey) {
			return nil
		}
	}
	return fmt.Errorf("trust anchor: publisher %s is not on the trusted-publishers list", m.Store.Publisher)
}

// VerifySignature checks that Store.Signature is a valid ed25519
// signature over the signing payload, verified against the Store.Publisher
// key embedded in the manifest. This provides cryptographic integrity —
// tampering with any manifest field that feeds the signing payload
// (Publisher, ID, ManifestVersion, Binary.SHA256, Grants) will cause
// verification to fail.
//
// IMPORTANT: This does NOT check that Store.Publisher is a trusted key.
// Callers MUST also call VerifyTrustAnchor() after VerifySignature()
// to confirm the publisher is on the TrustedPublishers list.
func (m *Manifest) VerifySignature() error {
	pubkeyRaw, ok := strings.CutPrefix(m.Store.Publisher, "ed25519:")
	if !ok {
		return fmt.Errorf("store.publisher must be \"ed25519:<base64>\"")
	}
	pubkey, err := base64.StdEncoding.DecodeString(pubkeyRaw)
	if err != nil {
		return fmt.Errorf("store.publisher: invalid base64: %w", err)
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("store.publisher: wrong key length %d, want %d", len(pubkey), ed25519.PublicKeySize)
	}

	sigRaw := m.Store.Signature
	// Accept optional "ed25519:" prefix on the signature too, for symmetry.
	sigRaw = strings.TrimPrefix(sigRaw, "ed25519:")
	sig, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil {
		return fmt.Errorf("store.signature: invalid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("store.signature: wrong signature length %d, want %d", len(sig), ed25519.SignatureSize)
	}

	payload, err := m.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubkey, payload, sig) {
		return fmt.Errorf("store.signature: verification failed — manifest may have been tampered with")
	}
	return nil
}
