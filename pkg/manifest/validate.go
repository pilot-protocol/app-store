package manifest

import (
	"fmt"
	"regexp"
	"strings"
)

// Known capability vocabulary. The runtime extends this list; manifests
// declaring unknown caps are rejected because the daemon wouldn't know how
// to broker them.
var KnownCaps = map[string]bool{
	"fs.read":   true,
	"fs.write":  true,
	"fs.append": true,
	"fs.delete": true,
	"net.dial":  true,
	"net.call":  true,
	"ipc.call":  true,
	"key.sign":  true,
	"audit.log": true,
}

// Known condition kinds.
var KnownConditionKinds = map[string]bool{
	"rate":                  true,
	"cap":                   true,
	"allowlist":             true,
	"denylist":              true,
	"time_window":           true,
	"requires_user_consent": true,
	"requires_foreground":   true,
	"signed_by":             true,
}

// Known binary runtimes.
var KnownRuntimes = map[string]bool{
	"go":     true,
	"bun":    true,
	"node":   true,
	"python": true,
}

// hookPointPattern matches "<command>.<pre|post>" where command is one
// or more dot-separated alphanum/hyphen/underscore segments. Mirrors
// pkg/extend's IsValid — kept duplicated so manifest validation runs
// without cross-package coupling.
//
// The command space is intentionally open: apps may declare hooks on
// app-defined commands (e.g. "wallet.pay.pre"), pilotctl subcommands
// (e.g. "appstore.install.pre"), or future daemon primitives without
// requiring a manifest-schema change.
var hookPointPattern = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.(pre|post)$`)

// KnownFlagTypes for Extension.AddsFlags.
var KnownFlagTypes = map[string]bool{
	"string": true,
	"bool":   true,
	"int":    true,
}

// Known protection levels.
var KnownProtections = map[string]bool{
	"":          true, // empty → default "shareable"
	"shareable": true,
	"guarded":   true,
}

// idPattern: reverse-DNS-ish identifiers. Letters/digits/underscores/dashes
// within each dot-separated segment; at least two segments; no leading/trailing
// dot; no double dots.
var idSegment = `[a-z0-9]([a-z0-9_-]*[a-z0-9])?`
var idPattern = regexp.MustCompile(`^` + idSegment + `(\.` + idSegment + `)+$`)

// semverPattern: simplified semver (MAJOR.MINOR.PATCH with optional -prerelease).
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)

// sha256Pattern: exactly 64 lowercase hex chars.
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pubkeyPattern: "ed25519:" + base64. Length flexible; format prefix required.
var pubkeyPattern = regexp.MustCompile(`^ed25519:[A-Za-z0-9+/=]{40,}$`)

// Validate checks a manifest against the schema rules. Returns ALL errors
// found (not just the first), so callers can fix them in one pass.
func (m *Manifest) Validate() []error {
	var errs []error

	if !idPattern.MatchString(m.ID) {
		errs = append(errs, fmt.Errorf("id %q must be reverse-DNS-shaped (e.g. io.pilot.wallet)", m.ID))
	}
	if !semverPattern.MatchString(m.AppVersion) {
		errs = append(errs, fmt.Errorf("app_version %q must be semver (e.g. 1.4.7)", m.AppVersion))
	}
	if m.ManifestVersion < 1 {
		errs = append(errs, fmt.Errorf("manifest_version must be >= 1, got %d", m.ManifestVersion))
	}

	// Binary
	if !KnownRuntimes[m.Binary.Runtime] {
		errs = append(errs, fmt.Errorf("binary.runtime %q is not one of: go, bun, node, python", m.Binary.Runtime))
	}
	if strings.TrimSpace(m.Binary.Path) == "" {
		errs = append(errs, fmt.Errorf("binary.path must not be empty"))
	}
	if !sha256Pattern.MatchString(m.Binary.SHA256) {
		errs = append(errs, fmt.Errorf("binary.sha256 must be 64 lowercase hex chars"))
	}

	// Grants
	if len(m.Grants) == 0 {
		errs = append(errs, fmt.Errorf("manifest must declare at least one grant"))
	}
	for i, g := range m.Grants {
		errs = append(errs, validateGrant(i, g)...)
	}

	// Protection
	if !KnownProtections[m.Protection] {
		errs = append(errs, fmt.Errorf("protection %q must be empty, \"shareable\", or \"guarded\"", m.Protection))
	}

	// Store
	if !pubkeyPattern.MatchString(m.Store.Publisher) {
		errs = append(errs, fmt.Errorf("store.publisher must be \"ed25519:<base64>\""))
	}
	if strings.TrimSpace(m.Store.Signature) == "" {
		errs = append(errs, fmt.Errorf("store.signature must not be empty"))
	}

	// Affiliates
	for i, a := range m.Affiliates {
		if !pubkeyPattern.MatchString(a.Pubkey) {
			errs = append(errs, fmt.Errorf("affiliates[%d].pubkey must be \"ed25519:<base64>\"", i))
		}
		if strings.TrimSpace(a.Role) == "" {
			errs = append(errs, fmt.Errorf("affiliates[%d].role must not be empty", i))
		}
	}

	// Depends
	for i, d := range m.Depends {
		if !idPattern.MatchString(d.App) {
			errs = append(errs, fmt.Errorf("depends[%d].app %q must be reverse-DNS-shaped", i, d.App))
		}
		if len(d.Methods) == 0 {
			errs = append(errs, fmt.Errorf("depends[%d].methods must not be empty", i))
		}
	}

	// Extends
	exposesSet := make(map[string]bool, len(m.Exposes))
	for _, e := range m.Exposes {
		exposesSet[e] = true
	}
	for i, ext := range m.Extends {
		if !hookPointPattern.MatchString(ext.Primitive) {
			errs = append(errs, fmt.Errorf("extends[%d].primitive %q must be <command>.<pre|post>", i, ext.Primitive))
		}
		if strings.TrimSpace(ext.Method) == "" {
			errs = append(errs, fmt.Errorf("extends[%d].method must not be empty", i))
		} else if len(m.Exposes) > 0 && !exposesSet[ext.Method] {
			// If an `exposes` list is declared, the hook method must be in it
			// — otherwise the daemon would have nothing to dispatch to. We
			// skip the check when exposes is empty (legacy / minimal manifests).
			errs = append(errs, fmt.Errorf("extends[%d].method %q must appear in exposes", i, ext.Method))
		}
		for j, f := range ext.AddsFlags {
			if !strings.HasPrefix(f.Name, "--") {
				errs = append(errs, fmt.Errorf("extends[%d].adds_flags[%d].name %q must start with --", i, j, f.Name))
			}
			if !KnownFlagTypes[f.Type] {
				errs = append(errs, fmt.Errorf("extends[%d].adds_flags[%d].type %q must be string|bool|int", i, j, f.Type))
			}
		}
	}

	// DynamicExtends — each entry must be a shape-valid hook point.
	for i, p := range m.DynamicExtends {
		if !hookPointPattern.MatchString(p) {
			errs = append(errs, fmt.Errorf("dynamic_extends[%d] %q must be <command>.<pre|post>", i, p))
		}
	}

	return errs
}

func validateGrant(i int, g Grant) []error {
	var errs []error
	if !KnownCaps[g.Cap] {
		errs = append(errs, fmt.Errorf("grants[%d].cap %q is not a known capability", i, g.Cap))
	}
	if strings.TrimSpace(g.Target) == "" {
		errs = append(errs, fmt.Errorf("grants[%d].target must not be empty", i))
	}
	if g.Condition != nil {
		errs = append(errs, validateCondition(fmt.Sprintf("grants[%d].if", i), *g.Condition)...)
	}
	return errs
}

func validateCondition(path string, c Condition) []error {
	var errs []error
	hasLeaf := c.Kind != "" || len(c.Params) > 0
	hasComposite := c.Op != "" || len(c.Compose) > 0

	if hasLeaf && hasComposite {
		errs = append(errs, fmt.Errorf("%s: cannot be both leaf (kind/params) and composite (op/compose)", path))
		return errs
	}
	if !hasLeaf && !hasComposite {
		errs = append(errs, fmt.Errorf("%s: must specify either kind or op", path))
		return errs
	}
	if hasLeaf {
		if !KnownConditionKinds[c.Kind] {
			errs = append(errs, fmt.Errorf("%s.kind %q is not a known condition kind", path, c.Kind))
		}
	}
	if hasComposite {
		switch c.Op {
		case "and", "or":
			if len(c.Compose) < 2 {
				errs = append(errs, fmt.Errorf("%s: %s needs at least 2 sub-conditions", path, c.Op))
			}
		case "not":
			if len(c.Compose) != 1 {
				errs = append(errs, fmt.Errorf("%s: not needs exactly 1 sub-condition", path))
			}
		default:
			errs = append(errs, fmt.Errorf("%s.op %q must be and|or|not", path, c.Op))
		}
		for i, sub := range c.Compose {
			errs = append(errs, validateCondition(fmt.Sprintf("%s.compose[%d]", path, i), sub)...)
		}
	}
	return errs
}
