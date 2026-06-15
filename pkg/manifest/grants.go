package manifest

import "strings"

// ExposesMethod reports whether method appears in the manifest's Exposes
// list. Exposes is the app's entire broker surface: the daemon's app-store
// broker dispatches a method into an app only if the app explicitly
// exposes it. An empty Exposes list therefore means "no broker-callable
// methods" — fail-closed.
func (m *Manifest) ExposesMethod(method string) bool {
	for _, e := range m.Exposes {
		if e == method {
			return true
		}
	}
	return false
}

// HasGrant reports whether the manifest declares a grant whose capability
// equals capName and whose target matches the requested target. Used by
// the broker to authorize cross-app ipc.call dispatch: the calling app
// must declare an `ipc.call` grant targeting the specific "<app>.<method>"
// it wants to reach.
//
// Target matching supports three forms, in order of generality:
//   - "*"           matches any target (blanket grant)
//   - "<prefix>.*"  matches any target sharing the prefix (e.g.
//     "io.pilot.wallet.*" matches "io.pilot.wallet.pay")
//   - exact         the grant target equals the requested target verbatim
//
// Conditions on the grant are NOT evaluated here — HasGrant answers only
// "is this capability+target declared". Per-request condition evaluation
// (rate, consent, time-window, …) is a separate, later gate.
func (m *Manifest) HasGrant(capName, target string) bool {
	for _, g := range m.Grants {
		if g.Cap == capName && matchGrantTarget(g.Target, target) {
			return true
		}
	}
	return false
}

// matchGrantTarget implements the target pattern rules documented on
// HasGrant.
func matchGrantTarget(pattern, target string) bool {
	switch {
	case pattern == "*":
		return true
	case pattern == target:
		return true
	case strings.HasSuffix(pattern, ".*"):
		// Keep the trailing dot so "io.app.*" matches "io.app.x" but
		// not "io.apple.x".
		return strings.HasPrefix(target, strings.TrimSuffix(pattern, "*"))
	default:
		return false
	}
}
