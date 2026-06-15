// Package extend is the hook registry that lets installed apps modify the
// daemon's existing primitives. Apps declare their hooks in the manifest
// `extends` field; at app-start the runtime registers them here; daemon
// primitives consult the registry and run the hook chain inline.
//
// The model: a primitive (send-message, recv, net.call, ...) is a sequence
// of hook chains around its core logic — PreX, core, PostX. Each hook is
// an IPC call to an installed app. The app may transform the HookArgs
// (the request/response payload) before returning. Later hooks see the
// transformed args, so apps stack predictably.
//
// Hooks are not authority-bearing — they cannot bypass the daemon's
// broker; they cannot grant themselves permissions; the daemon's existing
// safety floor (grants, deny-by-default) applies to every IPC call the
// hook makes back into the broker. A hook is a *transformer*, not a
// privileged kernel module.
package extend

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// HookPoint identifies one extensible step in a command's execution.
// Format: "<command>.<phase>" where:
//
//   - <command> is any reverse-DNS-ish name ("send-message",
//     "wallet.pay", "appstore.install", "memories.recall", ...).
//     Daemon built-ins, app-defined commands, and pilotctl subcommands
//     all use the same namespace — anything the runtime wraps with
//     Registry.Run is a hook point.
//
//   - <phase> is one of "pre" (runs before the core; may transform args
//     or abort with an error) or "post" (runs after the core; sees the
//     result; cannot un-run).
//
// The command space is open — apps can register hooks against
// commands no daemon-or-app wraps yet; those hooks are inert until
// something wraps the point. This lets apps anticipate future
// extension targets.
type HookPoint string

// Phase enumerates the two universal hook positions around a command's
// core logic. The command name is free, the phase is not.
type Phase string

const (
	PhasePre  Phase = "pre"
	PhasePost Phase = "post"
)

// hookPointPattern enforces the shape "<segment>(.<segment>)*.(pre|post)"
// where each segment is alphanum + hyphen + underscore. This keeps the
// space open without admitting arbitrary garbage (whitespace, dots in
// odd places, empty segments).
var hookPointPattern = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.(pre|post)$`)

// Common built-in hook points the daemon wraps. These are just
// well-known string values — there is no whitelist enforcement; any
// shape-valid HookPoint is accepted.
const (
	PreSendMessage  HookPoint = "send-message.pre"
	PostSendMessage HookPoint = "send-message.post"
	PostRecvMessage HookPoint = "recv.post"
	PreNetCall      HookPoint = "net.call.pre"
	PostNetCall     HookPoint = "net.call.post"
)

// IsValid reports whether s has the form "<command>.<phase>". Caller is
// expected to use this when accepting hook points from an untrusted
// source (e.g. parsing a manifest). The Registry calls it itself on
// Register, so apps cannot smuggle malformed points into the runtime.
func IsValid(s string) bool { return hookPointPattern.MatchString(s) }

// FlagSpec describes one CLI flag an app contributes to a primitive via
// a hook. Pilotctl asks the registry for all flags contributed at a
// given hook point before parsing args, so apps shape the CLI surface.
type FlagSpec struct {
	Name string `json:"name"` // "--paywall" — must include leading dashes
	Type string `json:"type"` // "string" | "bool" | "int"
	Help string `json:"help,omitempty"`
}

// Extension is one registered hook. AppID + Method together name the
// IPC endpoint the registry dispatches to.
type Extension struct {
	AppID     string
	Primitive HookPoint
	Method    string     // IPC method name on the app, e.g. "wallet.hookPreSendMessage"
	AddsFlags []FlagSpec // flags this hook contributes to its primitive's CLI
	Order     int        // lower runs earlier in the chain
	Version   string     // optional version string recorded in HookStamp
}

// HookArgs is the request/response payload passed through a hook chain.
// Generic map for now; per-hook-point schemas are documented in the
// HookPoint constants above. JSON-serializable.
type HookArgs map[string]any

// Dispatcher is how the registry calls an app's hook method. The
// app-store plugin wires this to its IPC client pool; tests inject a
// closure that runs hooks in-process.
type Dispatcher func(ctx context.Context, appID, method string, args HookArgs) (HookArgs, error)

// Registry holds all registered extensions. Safe for concurrent reads
// after Register/Unregister; the dispatch path takes only a read lock.
type Registry struct {
	dispatch Dispatcher

	mu      sync.RWMutex
	byPoint map[HookPoint][]Extension

	// limiter, when non-nil, rate-limits hook dispatch per app in Run.
	// Nil = unlimited (default); enable via SetRateLimit.
	limiter *rateLimiter
}

// ErrRateLimited is returned by Run when an app's hook-invocation rate
// budget is exhausted. The chain aborts rather than dispatch into an app
// that's being called too aggressively.
var ErrRateLimited = errors.New("extend: hook rate limit exceeded")

// NewRegistry constructs an empty Registry. dispatch is required.
func NewRegistry(dispatch Dispatcher) *Registry {
	if dispatch == nil {
		// Cheap defense — a registry without a dispatch is unusable; we
		// still let it construct so unit tests that only Register can
		// run, but Run() will error out.
		dispatch = func(context.Context, string, string, HookArgs) (HookArgs, error) {
			return nil, errors.New("extend: no dispatcher configured")
		}
	}
	return &Registry{
		dispatch: dispatch,
		byPoint:  map[HookPoint][]Extension{},
	}
}

// SetRateLimit enables per-app hook-dispatch rate limiting: each app may
// fire `burst` hook invocations instantly and `ratePerSec` sustained
// thereafter. Once an app's budget is exhausted, Run aborts that app's
// hook with ErrRateLimited. Call with a non-positive rate or burst to
// disable. Intended to be set once at daemon wire-up.
func (r *Registry) SetRateLimit(ratePerSec float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ratePerSec <= 0 || burst <= 0 {
		r.limiter = nil
		return
	}
	r.limiter = newRateLimiter(ratePerSec, burst)
}

// CountForApp returns the number of currently-registered extensions
// belonging to appID across all hook points. Used to bound how many
// dynamic registrations a single app may hold.
func (r *Registry) CountForApp(appID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, list := range r.byPoint {
		for _, ext := range list {
			if ext.AppID == appID {
				n++
			}
		}
	}
	return n
}

// Register adds one extension to the registry. Returns an error if
// the primitive is shape-invalid, the method is empty, or a flag is
// shaped wrong. Multiple apps may register for the same hook point;
// the point itself does not need to be "known" — registering against
// an unwrapped point is allowed and inert until something wraps it.
func (r *Registry) Register(ext Extension) error {
	if !IsValid(string(ext.Primitive)) {
		return fmt.Errorf("extend: malformed hook point %q (want <command>.<pre|post>)", ext.Primitive)
	}
	if strings.TrimSpace(ext.Method) == "" {
		return errors.New("extend: method required")
	}
	if strings.TrimSpace(ext.AppID) == "" {
		return errors.New("extend: app_id required")
	}
	for _, f := range ext.AddsFlags {
		if !strings.HasPrefix(f.Name, "--") {
			return fmt.Errorf("extend: flag %q must start with --", f.Name)
		}
		switch f.Type {
		case "string", "bool", "int":
		default:
			return fmt.Errorf("extend: flag %q has unknown type %q", f.Name, f.Type)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	list := append(r.byPoint[ext.Primitive], ext)
	// Stable sort by Order — lower runs earlier. Apps with the same
	// Order run in registration order (sort.Slice is not stable but the
	// SliceStable variant is).
	sort.SliceStable(list, func(i, j int) bool { return list[i].Order < list[j].Order })
	r.byPoint[ext.Primitive] = list
	return nil
}

// Unregister removes all hooks belonging to appID. Called when an app
// is uninstalled or suspended. Idempotent.
func (r *Registry) Unregister(appID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p, list := range r.byPoint {
		out := list[:0]
		for _, ext := range list {
			if ext.AppID != appID {
				out = append(out, ext)
			}
		}
		r.byPoint[p] = out
	}
}

// HooksFor returns the registered extensions for a hook point, in run
// order. Safe to call concurrently.
func (r *Registry) HooksFor(p HookPoint) []Extension {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.byPoint[p]
	out := make([]Extension, len(src))
	copy(out, src)
	return out
}

// AllRegistered returns every registered extension across every hook
// point. Used by the runtime-register IPC's List method for
// introspection.
func (r *Registry) AllRegistered() []Extension {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Extension
	for _, list := range r.byPoint {
		out = append(out, list...)
	}
	return out
}

// FlagsFor returns the union of flag specs contributed at a hook
// point. Pilotctl uses this to extend its CLI surface dynamically.
// Duplicate flag names across apps are returned as duplicates — the
// caller should detect collisions and decide a resolution.
func (r *Registry) FlagsFor(p HookPoint) []FlagSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []FlagSpec
	for _, ext := range r.byPoint[p] {
		out = append(out, ext.AddsFlags...)
	}
	return out
}

// Run executes the hook chain for a point, threading args through each
// hook in order. Any hook returning an error aborts the chain and the
// caller's primitive call.
//
// args is treated as mutable — the hook may modify in place — but for
// safety the registry passes a shallow copy on each call so a misbehaving
// hook can't mutate args from under a later hook unexpectedly.
//
// After each successful hook return, the registry appends a HookStamp
// to args["__meta"].TouchedBy. The stamp's AppID + Primitive come from
// the registry (the hook can't lie about who it is); Details and
// Required are read from scratch keys (__meta_details, __meta_required)
// the hook may have populated, then cleared.
func (r *Registry) Run(ctx context.Context, p HookPoint, args HookArgs) (HookArgs, error) {
	hooks := r.HooksFor(p)
	r.mu.RLock()
	lim := r.limiter
	r.mu.RUnlock()
	current := args
	for _, h := range hooks {
		if err := ctx.Err(); err != nil {
			return current, err
		}
		if lim != nil && !lim.allow(h.AppID) {
			return current, fmt.Errorf("extend %s: hook %s.%s: %w", p, h.AppID, h.Method, ErrRateLimited)
		}
		next, err := r.dispatch(ctx, h.AppID, h.Method, cloneArgs(current))
		if err != nil {
			return current, fmt.Errorf("extend %s: hook %s.%s: %w", p, h.AppID, h.Method, err)
		}
		if next != nil {
			current = next
		}
		// Auto-stamp regardless of whether the hook returned next or
		// mutated in place. The hook contributes Details/Required via
		// scratch keys; the registry consumes them and clears.
		stampAndConsume(current, h.AppID, p, h.Version, time.Now().UTC())
	}
	return current, nil
}

// UnregisterOne removes a specific (appID, primitive, method) triple.
// Used by the runtime-register IPC surface to undo a single dynamic
// registration without dropping the rest of an app's hooks.
func (r *Registry) UnregisterOne(appID string, primitive HookPoint, method string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.byPoint[primitive]
	out := list[:0]
	for _, ext := range list {
		if ext.AppID == appID && ext.Method == method {
			continue
		}
		out = append(out, ext)
	}
	r.byPoint[primitive] = out
}

func cloneArgs(a HookArgs) HookArgs {
	if a == nil {
		return HookArgs{}
	}
	out := make(HookArgs, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}
