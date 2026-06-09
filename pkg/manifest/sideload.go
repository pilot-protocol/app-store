// Sideload policy: the rule set a manifest must satisfy when an app
// is installed from a local path (not the signed catalogue).
//
// Catalogue apps are published by a trusted store key and may declare
// arbitrary grants the user accepts at install time. Sideloaded apps
// did not go through that review and are intentionally clamped: the
// allow-list below is the only thing they can ask for. Anything else
// in the manifest — wider fs paths, network, signing keys, daemon
// hooks, affiliates — fails policy and the supervisor refuses to load
// the app.
//
// This is a MANIFEST gate. It guarantees that no sideloaded app's
// declared surface escapes the allow-list. It does NOT prevent a
// hostile binary from ignoring its declarations at the syscall layer
// (that's the job of an OS sandbox — see SideloadOSSandboxTODO).

package manifest

import (
	"fmt"
	"strings"
)

// SideloadMarkerName is the sentinel file whose presence in an install
// directory flips an app into sideloaded mode. The pilotctl install
// command writes this when invoked with --local; absence is the
// default (catalogue install). Keeping it as a file (not a manifest
// field) means a tampered manifest can never claim "I'm a catalogue
// app" — the file's existence is the trust signal, and only the
// install command writes it.
const SideloadMarkerName = ".sideloaded"

// SideloadAllowedCaps is the closed set of capability strings a
// sideloaded manifest may declare. Order doesn't matter; membership
// is exact-match.
var SideloadAllowedCaps = map[string]struct{}{
	"audit.log": {},
	"fs.read":   {},
	"fs.write":  {},
}

// SideloadOSSandboxTODO is a marker constant referenced from places
// that need to remember sideload safety today is manifest-gate-only.
// When OS sandboxing lands (linux landlock + seccomp + net unshare,
// macOS sandbox-exec), search-and-remove this constant and update the
// CLI warning printed at install time.
const SideloadOSSandboxTODO = "TODO(sandbox): OS-level isolation not yet wired; sideload safety is manifest-gate only"

// EnforceSideloadPolicy checks a parsed manifest against the sideload
// allow-list. Returns nil iff every grant, extension, affiliate, and
// protection setting fits the policy. The error message lists the
// FIRST violation; callers should fix-and-retry rather than expecting
// a complete enumeration in one pass.
//
// The check is strict by design: anything unrecognised is denied, so
// adding a new cap kind to the manifest schema doesn't silently widen
// the sideload surface. Allowing a new cap for sideloads is an
// intentional, reviewable change to SideloadAllowedCaps.
func EnforceSideloadPolicy(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("sideload policy: nil manifest")
	}
	if m.Protection == "guarded" {
		return fmt.Errorf(`sideload policy: protection="guarded" is reserved for catalogue apps (got %q)`, m.Protection)
	}
	if len(m.Extends) != 0 {
		return fmt.Errorf("sideload policy: extends not permitted (manifest declares %d hook(s); first: %q)",
			len(m.Extends), m.Extends[0].Primitive)
	}
	if len(m.DynamicExtends) != 0 {
		return fmt.Errorf("sideload policy: dynamic_extends not permitted (manifest declares %d: first %q)",
			len(m.DynamicExtends), m.DynamicExtends[0])
	}
	if len(m.Affiliates) != 0 {
		return fmt.Errorf("sideload policy: affiliates not permitted (manifest declares %d; first role %q)",
			len(m.Affiliates), m.Affiliates[0].Role)
	}
	for i, d := range m.Depends {
		// Sideloads may not depend on other apps; cross-app IPC is the
		// most powerful escalation path (a sideload could DM the
		// wallet's sign methods). Apps that legitimately need other
		// apps go through the catalogue.
		_ = d
		return fmt.Errorf("sideload policy: depends not permitted (manifest declares %d at index %d)", len(m.Depends), i)
	}
	for i, g := range m.Grants {
		if _, ok := SideloadAllowedCaps[g.Cap]; !ok {
			return fmt.Errorf("sideload policy: grant[%d] cap=%q not in allow-list (permitted: %s)",
				i, g.Cap, joinSideloadAllowed())
		}
		switch g.Cap {
		case "fs.read", "fs.write":
			if !isAppLocalTarget(g.Target) {
				return fmt.Errorf("sideload policy: grant[%d] %s target %q must be under $APP/", i, g.Cap, g.Target)
			}
		case "audit.log":
			// "*" is the only meaningful target for audit.log today;
			// accept any string here since the runtime treats audit.log
			// as a local-only logging primitive.
		}
		if g.Condition != nil {
			// Conditions on a clamped allow-list are pointless — every
			// allowed cap is already locally scoped. Reject for clarity
			// rather than silently ignoring.
			return fmt.Errorf("sideload policy: grant[%d] %s carries an if-condition; sideloaded grants must be unconditional", i, g.Cap)
		}
	}
	return nil
}

// isAppLocalTarget enforces that an fs.read/fs.write target points
// inside the app's own install dir. The runtime uses "$APP/" as the
// expansion root for that directory. Anything outside ("/etc",
// "../foo", "$HOME/...") would let a sideloaded app touch the host
// FS — refused.
func isAppLocalTarget(t string) bool {
	t = strings.TrimSpace(t)
	if !strings.HasPrefix(t, "$APP/") {
		return false
	}
	rest := t[len("$APP/"):]
	if rest == "" {
		return false
	}
	if strings.Contains(rest, "..") {
		return false
	}
	if strings.HasPrefix(rest, "/") {
		return false
	}
	return true
}

func joinSideloadAllowed() string {
	out := make([]string, 0, len(SideloadAllowedCaps))
	for k := range SideloadAllowedCaps {
		out = append(out, k)
	}
	// Sort by hand so the error message is deterministic without
	// pulling in sort just for the lookup. Three strings; bubble-sort
	// is fine and keeps test diffs stable.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return strings.Join(out, ", ")
}
