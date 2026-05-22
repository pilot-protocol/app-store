package extend

import (
	"encoding/json"
	"time"
)

// WireMeta is the provenance trail that follows a hooked message on
// the wire. The Wrap helper populates it as hooks run; the daemon
// serializes it into the outbound envelope; the recipient parses it
// before attempting to decode the body. If any app in Required is not
// locally installed, the recipient surfaces that to the user instead
// of failing to decode.
//
// Cumulative across the whole hook chain. Receivers can also append
// their own stamps via post-recv hooks, producing a two-sided record
// of every app that touched the message.
type WireMeta struct {
	TouchedBy []HookStamp `json:"touched_by,omitempty"`
	Required  []string    `json:"required,omitempty"`
	Encoding  []string    `json:"encoding,omitempty"`
}

// HookStamp is one entry in the trail. App and Primitive are recorded
// by the registry — the hook can't lie about them. Details is the only
// part the hook controls; it's where the wallet writes its contract_id,
// where the compressor writes its algorithm, etc.
type HookStamp struct {
	AppID     string         `json:"app"`
	Primitive string         `json:"primitive"`
	Version   string         `json:"version,omitempty"`
	At        time.Time      `json:"at"`
	Details   map[string]any `json:"details,omitempty"`
}

// Reserved keys the framework uses inside HookArgs to thread meta
// through the chain. Hooks read/write these via the helpers below; the
// registry consumes them after each hook returns and clears the
// scratch slots.
const (
	metaKey     = "__meta"           // *WireMeta (or its JSON map form)
	detailsKey  = "__meta_details"   // map[string]any — hook contribution to next stamp
	requiredKey = "__meta_required"  // []string      — apps to add to WireMeta.Required
	encodingKey = "__meta_encoding"  // []string      — encoding labels to append
)

// GetMeta extracts the WireMeta from args. Returns an empty (non-nil)
// WireMeta if absent, so callers can safely append without nil checks.
func GetMeta(args HookArgs) *WireMeta {
	raw, ok := args[metaKey]
	if !ok || raw == nil {
		return &WireMeta{}
	}
	// Common cases: already a *WireMeta (in-process) or a map (JSON).
	if m, ok := raw.(*WireMeta); ok && m != nil {
		return m
	}
	// Generic JSON roundtrip handles map[string]any from an IPC hop.
	b, err := json.Marshal(raw)
	if err != nil {
		return &WireMeta{}
	}
	var m WireMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return &WireMeta{}
	}
	return &m
}

// SetMeta writes m back to args. Pass nil to clear.
func SetMeta(args HookArgs, m *WireMeta) {
	if m == nil {
		delete(args, metaKey)
		return
	}
	args[metaKey] = m
}

// SetDetails is a hook-side helper that contributes Details to the
// stamp the registry will append after this hook returns. Call inside
// the hook implementation, just before returning args.
func SetDetails(args HookArgs, details map[string]any) {
	if details == nil {
		delete(args, detailsKey)
		return
	}
	args[detailsKey] = details
}

// AddRequired is a hook-side helper that contributes appIDs to the
// cumulative WireMeta.Required list. The framework de-duplicates.
func AddRequired(args HookArgs, appIDs ...string) {
	if len(appIDs) == 0 {
		return
	}
	existing, _ := args[requiredKey].([]string)
	existing = append(existing, appIDs...)
	args[requiredKey] = existing
}

// AddEncoding contributes one or more encoding labels (in order) to
// WireMeta.Encoding. Mirrors HTTP Content-Encoding chaining: the last
// label is the outermost transform, applied first by senders and
// reversed last by receivers.
func AddEncoding(args HookArgs, codings ...string) {
	if len(codings) == 0 {
		return
	}
	existing, _ := args[encodingKey].([]string)
	existing = append(existing, codings...)
	args[encodingKey] = existing
}

// MissingRequired returns the apps in meta.Required that aren't in
// installed. Recipient daemons call this on incoming messages before
// post-recv dispatch — if non-empty, the daemon surfaces the missing
// apps to the user instead of trying to decode.
func MissingRequired(meta *WireMeta, installed []string) []string {
	if meta == nil || len(meta.Required) == 0 {
		return nil
	}
	have := make(map[string]bool, len(installed))
	for _, id := range installed {
		have[id] = true
	}
	var missing []string
	for _, id := range meta.Required {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// stampAndConsume is called by the registry after each successful
// hook return. It moves the hook's contributions (__meta_details,
// __meta_required, __meta_encoding) into a fresh HookStamp and
// merges them into the cumulative WireMeta. Scratch slots are cleared
// so the next hook starts clean.
func stampAndConsume(args HookArgs, appID string, primitive HookPoint, version string, now time.Time) {
	meta := GetMeta(args)

	stamp := HookStamp{
		AppID:     appID,
		Primitive: string(primitive),
		Version:   version,
		At:        now,
	}
	if d, ok := args[detailsKey].(map[string]any); ok && len(d) > 0 {
		stamp.Details = d
	}
	meta.TouchedBy = append(meta.TouchedBy, stamp)

	if r, ok := args[requiredKey].([]string); ok && len(r) > 0 {
		meta.Required = appendUnique(meta.Required, r...)
	}
	if e, ok := args[encodingKey].([]string); ok && len(e) > 0 {
		meta.Encoding = append(meta.Encoding, e...)
	}

	// Clear scratch slots before the next hook runs.
	delete(args, detailsKey)
	delete(args, requiredKey)
	delete(args, encodingKey)

	SetMeta(args, meta)
}

func appendUnique(dst []string, src ...string) []string {
	have := make(map[string]bool, len(dst))
	for _, s := range dst {
		have[s] = true
	}
	for _, s := range src {
		if !have[s] {
			dst = append(dst, s)
			have[s] = true
		}
	}
	return dst
}
