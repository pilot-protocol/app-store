// Package manifest defines the typed schema for a pilot app manifest.
//
// The manifest is the *only* source of truth for an app's grants — the runtime
// never infers permissions from anywhere else. Pinned at install time and
// re-verified on every launch.
//
// See ../docs/architecture/graph.json (node id: "manifest") for the canonical
// description; this file is the Go embodiment of that node.
package manifest

import "encoding/json"

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
