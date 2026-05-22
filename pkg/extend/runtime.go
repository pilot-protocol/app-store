package extend

import (
	"errors"
	"fmt"
)

// Permission is the gate the daemon's runtime-register IPC consults
// before adding a hook to the registry on behalf of an app. The default
// implementation in the appstore plugin grants a (appID, primitive)
// pair only if the manifest's `dynamic_extends` list includes
// primitive — i.e. the app declared at install time that it might
// register this point later.
//
// Daemons / tests may swap in stricter policies (per-user prompt,
// allowlist file, …) without touching extend's wiring.
type Permission interface {
	CanRegister(appID string, primitive HookPoint) bool
}

// PermissionFunc adapts an ordinary function to the Permission interface.
type PermissionFunc func(appID string, primitive HookPoint) bool

// CanRegister forwards to the wrapped function.
func (f PermissionFunc) CanRegister(appID string, primitive HookPoint) bool { return f(appID, primitive) }

// AllowAll is a permission that grants any registration. Convenient
// for tests; never use as production default.
var AllowAll Permission = PermissionFunc(func(string, HookPoint) bool { return true })

// DenyAll rejects every registration. Useful as a safe default before
// a real Permission is wired.
var DenyAll Permission = PermissionFunc(func(string, HookPoint) bool { return false })

// ErrPermissionDenied is returned by DaemonHandler.Register when the
// configured Permission rejects the request.
var ErrPermissionDenied = errors.New("extend: permission denied")

// DaemonHandler is the runtime-side IPC surface the daemon exposes to
// installed apps so they can add/remove their own hooks dynamically
// (within the bounds Permission allows). Apps call these methods via
// the daemon's normal IPC broker — the broker enforces the per-app
// `ipc.call:extend.register` grant first; if that passes, the call
// lands here, and Permission gates which hook points are reachable.
type DaemonHandler struct {
	reg   *Registry
	perms Permission
}

// NewDaemonHandler returns a handler bound to a Registry. If perms is
// nil, DenyAll is used.
func NewDaemonHandler(reg *Registry, perms Permission) *DaemonHandler {
	if perms == nil {
		perms = DenyAll
	}
	return &DaemonHandler{reg: reg, perms: perms}
}

// Register is called by apps to install a hook at runtime. AppID is set
// by the daemon's broker from the calling app's identity, not by the
// caller — the app can't impersonate someone else.
func (h *DaemonHandler) Register(appID string, ext Extension) error {
	if ext.AppID == "" {
		ext.AppID = appID
	} else if ext.AppID != appID {
		return fmt.Errorf("extend: cannot register on behalf of another app (caller=%s, claimed=%s)", appID, ext.AppID)
	}
	if !h.perms.CanRegister(appID, ext.Primitive) {
		return fmt.Errorf("%w: %s cannot register %s", ErrPermissionDenied, appID, ext.Primitive)
	}
	return h.reg.Register(ext)
}

// Unregister removes a previously-registered hook. Apps may only
// unregister their own hooks; the (appID, primitive, method) triple
// is the unique key.
func (h *DaemonHandler) Unregister(appID string, primitive HookPoint, method string) error {
	if !IsValid(string(primitive)) {
		return fmt.Errorf("extend: malformed hook point %q", primitive)
	}
	h.reg.UnregisterOne(appID, primitive, method)
	return nil
}

// List returns all currently-registered extensions, optionally
// filtered by primitive. Used for introspection (pilotctl extend list).
func (h *DaemonHandler) List(primitive HookPoint) []Extension {
	if primitive == "" {
		return h.reg.AllRegistered()
	}
	return h.reg.HooksFor(primitive)
}
