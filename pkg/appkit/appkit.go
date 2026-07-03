// Package appkit gives apps small, composable helpers for acting on
// verified sender identity. There are two distinct paths by which an app
// learns who a request came from:
//
//  1. Daemon-attested origin. When the daemon bridges a request from a
//     remote Pilot node into an app, it stamps ipc.Envelope.Origin with the
//     peer identity it proved during the authenticated key exchange
//     (Service.CallWithOrigin). RequireOrigin and LimitPerNode consume that
//     block directly — no crypto in the app.
//
//  2. Out-of-band envelope verification. Traffic that did NOT come through
//     the daemon bridge (e.g. a signed blob relayed through another app or
//     fetched from storage) carries no attested origin. RequireEnvelope
//     instead expects the request payload to contain "pilot_envelope" and
//     "pilot_signature" fields and asks the daemon to verify them via a
//     VerifyFunc the app supplies.
//
// appkit is stdlib-only: it never imports the daemon driver. Apps wire the
// daemon's CmdVerifyEnvelope IPC in with a closure, e.g.:
//
//	drv := driver.Dial(...)
//	verify := func(envelope, signature string) (appkit.VerifyResult, error) {
//		res, err := drv.VerifyEnvelope(envelope, signature)
//		if err != nil {
//			return appkit.VerifyResult{}, err
//		}
//		return appkit.VerifyResult{
//			Valid:         res.Valid,
//			Node:          res.Node,
//			NodeID:        res.NodeID,
//			Authenticated: res.Authenticated,
//			Trusted:       res.Trusted,
//			Online:        res.Online,
//		}, nil
//	}
//	d.Register("pay", appkit.RequireEnvelope(verify, payHandler))
//
// Trust boundary: origin (attested or synthesized) is trustworthy exactly
// as far as the daemon socket is. A same-UID local process dialing app.sock
// directly can forge anything — same-UID is the platform trust boundary
// today (no OS sandbox). What appkit does guarantee is that no *app* can
// forge an origin through the broker: cross-app calls always arrive with
// Origin == nil.
package appkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// VerifyResult is what a VerifyFunc reports about a signed Pilot envelope.
// Mirrors the daemon's CmdVerifyEnvelope reply shape.
type VerifyResult struct {
	Valid         bool   // signature checks out against the claimed identity
	Node          string // text address, e.g. "1:0001.ABCD.1234"
	NodeID        uint32
	Authenticated bool // identity proven via key exchange with the daemon
	Trusted       bool // in the daemon's handshake trust store
	Online        bool // node currently reachable, per the daemon
}

// VerifyFunc asks the daemon to verify a signed envelope. Apps implement
// it as a closure over common/driver's VerifyEnvelope — see the package
// doc for an example. appkit never dials the daemon itself.
type VerifyFunc func(envelope, signature string) (VerifyResult, error)

// Sentinel errors returned by the middleware handlers. Compare with
// errors.Is; on the wire they surface as EnvErr messages.
var (
	// ErrOriginRequired rejects requests with no authenticated origin.
	ErrOriginRequired = errors.New("appkit: authenticated origin required")
	// ErrRateLimited rejects requests over the per-node budget.
	ErrRateLimited = errors.New("appkit: rate limit exceeded")
	// ErrEnvelopeRequired rejects payloads missing pilot_envelope /
	// pilot_signature (or with a payload that isn't a JSON object).
	ErrEnvelopeRequired = errors.New("appkit: pilot_envelope and pilot_signature required")
	// ErrEnvelopeInvalid rejects envelopes the daemon verified as not valid.
	ErrEnvelopeInvalid = errors.New("appkit: envelope verification failed")
)

// RequireOrigin wraps next so it only runs for requests carrying a
// daemon-attested, key-exchange-authenticated origin. Everything else —
// no origin at all (direct connection, cross-app call) or an origin the
// daemon could not authenticate — is rejected with ErrOriginRequired.
func RequireOrigin(next ipc.Handler) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		if req.Origin == nil || !req.Origin.Authenticated {
			return nil, ErrOriginRequired
		}
		return next(ctx, req)
	}
}

// LimitPerNode wraps next with a per-node-identity rate limit, keyed on
// Origin.Node. Compose it after RequireOrigin — but it is defensive on
// its own: a request with no origin (nothing to key on) is rejected with
// ErrOriginRequired rather than sharing one anonymous bucket.
func LimitPerNode(l *NodeLimiter, next ipc.Handler) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		if req.Origin == nil || req.Origin.Node == "" {
			return nil, ErrOriginRequired
		}
		if !l.Allow(req.Origin.Node) {
			return nil, fmt.Errorf("%w: %s", ErrRateLimited, req.Origin.Node)
		}
		return next(ctx, req)
	}
}

// RequireEnvelope wraps next for out-of-band traffic: requests whose
// payload carries a signed Pilot envelope instead of arriving through the
// daemon bridge. The payload must be a JSON object with non-empty
// "pilot_envelope" and "pilot_signature" string fields; verify is called
// on the pair, and on a Valid result the handler runs with a synthesized
// env.Origin built from the verification. Missing fields, unparseable
// payloads, verify errors, and invalid envelopes are all rejected.
//
// next receives a shallow copy of the request so the synthesized origin
// never leaks into the caller's envelope.
func RequireEnvelope(verify VerifyFunc, next ipc.Handler) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var wrap struct {
			Envelope  string `json:"pilot_envelope"`
			Signature string `json:"pilot_signature"`
		}
		if len(req.Payload) == 0 {
			return nil, ErrEnvelopeRequired
		}
		if err := json.Unmarshal(req.Payload, &wrap); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEnvelopeRequired, err)
		}
		if wrap.Envelope == "" || wrap.Signature == "" {
			return nil, ErrEnvelopeRequired
		}
		res, err := verify(wrap.Envelope, wrap.Signature)
		if err != nil {
			return nil, fmt.Errorf("appkit: verify envelope: %w", err)
		}
		if !res.Valid {
			return nil, ErrEnvelopeInvalid
		}
		attested := *req
		attested.Origin = &ipc.Origin{
			Node:          res.Node,
			NodeID:        res.NodeID,
			Authenticated: res.Authenticated,
			Trusted:       res.Trusted,
		}
		return next(ctx, &attested)
	}
}
