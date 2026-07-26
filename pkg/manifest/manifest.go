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
	//      "key.sign" | "audit.log" | "proc.exec" | ...
	Cap string `json:"cap"`

	// Target: path pattern, host pattern, "<app>.<method>", sign-purpose, or
	// (for proc.exec) the single executable the app may spawn — an absolute path
	// or a bare command name.
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
	// Signature: store's signature over the manifest signing payload. New
	// signatures use the v2 payload, which commits to the publisher key plus
	// a hash of the whole manifest; the older v1 payload covered only
	// (id || manifest_version || binary.sha256 || grants-hash) and is still
	// accepted on verify. See SigningPayload.
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

// SigningPayloadV2Prefix is the domain-separation tag that opens every v2
// signing payload. It keeps v2 payload bytes disjoint from v1 payload bytes,
// so a signature produced for one scheme can never verify under the other.
const SigningPayloadV2Prefix = "pilot.app-manifest.v2"

// AllowLegacySignaturePayload controls whether VerifySignature falls back to
// the v1 signing payload when the v2 payload does not verify. Manifests signed
// before v2 existed carry v1 signatures, so this defaults to true. Set it to
// false to accept v2 signatures only.
var AllowLegacySignaturePayload = true

// signingPayloadV1 builds the original canonical byte-string for
// Store.Signature. The publisher key is included so that a signature cannot
// be reused with a different publisher identity — swapping the publisher key
// invalidates the signature.
//
// Format: publisher || ":" || id || ":" || manifest_version || ":" || binary.sha256 || ":" || grants-sha256-hex
//
// It covers Store.Publisher, ID, ManifestVersion, Binary.SHA256 and Grants.
// Every other manifest field — Binary.Runtime, Binary.Path, Exposes,
// Protection, Affiliates, Depends, Extends, DynamicExtends, AppVersion — sits
// outside these bytes and can therefore be edited without disturbing a v1
// signature. signingPayloadV2 closes that gap.
func (m *Manifest) signingPayloadV1() ([]byte, error) {
	grantsJSON, err := canonicalJSON(m.Grants)
	if err != nil {
		return nil, fmt.Errorf("grants marshal: %w", err)
	}
	grantsHash := sha256.Sum256(grantsJSON)
	payload := fmt.Sprintf("%s:%s:%d:%s:%x",
		m.Store.Publisher, m.ID, m.ManifestVersion, m.Binary.SHA256, grantsHash)
	return []byte(payload), nil
}

// signingPayloadV2 builds the current canonical byte-string for
// Store.Signature. It commits to the whole manifest rather than a hand-picked
// subset: the payload is the domain-separation prefix, the publisher key, and
// the sha256 of the canonical JSON encoding of the manifest with
// Store.Signature blanked out.
//
// Blanking Store.Signature is what makes the hash computable on both sides —
// the signer does not yet have a signature, and the verifier must reproduce
// the same pre-signature bytes. Everything else is included verbatim, so any
// edit to Binary.Runtime, Binary.Path, Exposes, Protection, Affiliates,
// Depends, Extends, DynamicExtends or AppVersion changes the hash and the
// signature no longer verifies.
//
// Format: "pilot.app-manifest.v2" || ":" || publisher || ":" || manifest-sha256-hex
func (m *Manifest) signingPayloadV2() ([]byte, error) {
	// Shallow copy: only the Store.Signature scalar is rewritten, and the
	// copy is discarded once hashed, so the caller's manifest is untouched.
	unsigned := *m
	unsigned.Store.Signature = ""

	body, err := canonicalJSON(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("manifest marshal: %w", err)
	}
	bodyHash := sha256.Sum256(body)
	payload := fmt.Sprintf("%s:%s:%x", SigningPayloadV2Prefix, m.Store.Publisher, bodyHash)
	return []byte(payload), nil
}

// SigningPayload returns the bytes a publisher must sign to produce
// Store.Signature. New signatures use the v2 payload.
func (m *Manifest) SigningPayload() ([]byte, error) {
	return m.signingPayloadV2()
}

// Sign fills in Store.Signature with an ed25519 signature over the v2 signing
// payload and returns the base64 signature it stored. Store.Publisher must
// already be set to the "ed25519:<base64>" form of priv's public key, since the
// publisher string is part of the payload.
func (m *Manifest) Sign(priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key: wrong length %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pubkey, err := decodeEd25519Pub(m.Store.Publisher)
	if err != nil {
		return "", fmt.Errorf("store.publisher: %w", err)
	}
	if !bytes.Equal(pubkey, priv.Public().(ed25519.PublicKey)) {
		return "", fmt.Errorf("store.publisher does not match the signing key")
	}
	payload, err := m.signingPayloadV2()
	if err != nil {
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	m.Store.Signature = sig
	return sig, nil
}

// decodeEd25519Pub parses an "ed25519:<base64>" (or bare base64) public key
// into raw bytes, validating the length.
func decodeEd25519Pub(s string) ([]byte, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(s), "ed25519:")
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong key length %d, want %d", len(key), ed25519.PublicKeySize)
	}
	return key, nil
}

// VerifyTrustAnchor confirms that Store.Publisher matches the publisher key the
// release-signed catalogue pins for this app. This is the trust anchor for
// non-sideloaded (catalogue) installs: the catalogue is the root of trust
// (the installer verifies the catalogue signature and pins each app's bundle
// sha256), and this check re-confirms on every launch that the installed
// manifest is published by the catalogue-declared key.
//
// Without it, VerifySignature alone only proves a manifest is internally
// self-consistent — a manifest self-signed by ANY key would pass — which would
// let an app dropped into the install root run with full grants.
//
// cataloguePublisher is the "ed25519:<base64>" key the verified catalogue
// declares for m.ID; the caller (the supervisor) obtains it from the
// signature-verified catalogue via Config.CataloguePublisher. An empty string
// means the app is not pinned by the catalogue, which is fail-closed. Returns
// nil only when the manifest's publisher equals the catalogue-pinned key.
func (m *Manifest) VerifyTrustAnchor(cataloguePublisher string) error {
	if strings.TrimSpace(cataloguePublisher) == "" {
		return fmt.Errorf("trust anchor: %s is not pinned by the signed catalogue", m.ID)
	}
	pubkey, err := decodeEd25519Pub(m.Store.Publisher)
	if err != nil {
		return fmt.Errorf("store.publisher: %w", err)
	}
	trustedKey, err := decodeEd25519Pub(cataloguePublisher)
	if err != nil {
		return fmt.Errorf("catalogue publisher for %s: %w", m.ID, err)
	}
	if !bytes.Equal(pubkey, trustedKey) {
		return fmt.Errorf("trust anchor: publisher %s does not match the catalogue pin for %s", m.Store.Publisher, m.ID)
	}
	return nil
}

// VerifySignature checks that Store.Signature is a valid ed25519
// signature over a signing payload, verified against the Store.Publisher
// key embedded in the manifest.
//
// Two payload versions are accepted. The v2 payload commits to the entire
// manifest, so editing any field — including Binary.Path, Binary.Runtime,
// Exposes, Protection, Affiliates, Depends, Extends and DynamicExtends —
// invalidates the signature. The v1 payload covers only Publisher, ID,
// ManifestVersion, Binary.SHA256 and Grants; it is tried as a fallback while
// AllowLegacySignaturePayload is true so that manifests signed before v2 keep
// verifying. New signatures should be produced with Sign / SigningPayload,
// which emit v2.
//
// IMPORTANT: This does NOT check that Store.Publisher is trusted. For
// non-sideloaded apps, callers MUST also call VerifyTrustAnchor(cataloguePublisher)
// to confirm the publisher matches the key the signed catalogue pins for the app.
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

	payloadV2, err := m.signingPayloadV2()
	if err != nil {
		return err
	}
	if ed25519.Verify(pubkey, payloadV2, sig) {
		return nil
	}

	if AllowLegacySignaturePayload {
		payloadV1, err := m.signingPayloadV1()
		if err != nil {
			return err
		}
		if ed25519.Verify(pubkey, payloadV1, sig) {
			return nil
		}
	}

	return fmt.Errorf("store.signature: verification failed — manifest contents do not match the signature")
}
