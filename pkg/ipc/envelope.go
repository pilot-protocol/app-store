// Package ipc is the wire layer between a Pilot app (the wallet, for now)
// and the daemon that hosts it. Length-prefixed JSON envelopes carry
// requests and replies over any io.ReadWriter — typically a unix-domain
// socket the daemon hands to the app at spawn time, but anything
// duplex works (net.Pipe in tests, a TCP connection for remote dev).
//
// The wire is intentionally simple: 4-byte big-endian length + JSON
// envelope. Mirrors the pilot_header / ipc_envelope split in the
// architecture graph — framing here, semantics in the envelope.
package ipc

import "encoding/json"

// EnvelopeType discriminates the three kinds of envelopes that flow.
type EnvelopeType string

const (
	// EnvReq is a method call from caller to server.
	EnvReq EnvelopeType = "req"
	// EnvReply is a successful return from server to caller.
	EnvReply EnvelopeType = "reply"
	// EnvErr is a typed error return; never raw exceptions.
	EnvErr EnvelopeType = "err"
)

// Origin identifies the remote Pilot node a request originated from.
// It is DAEMON-ATTESTED: only the daemon bridge sets it, from peer identity
// proven during the authenticated key exchange. The broker strips any
// caller-supplied origin on cross-app calls so apps cannot forge it.
// Trust boundary: a same-UID local process dialing app.sock directly can
// forge anything — same-UID is the platform trust boundary today (no OS
// sandbox); origin is trustworthy exactly as far as the daemon socket is.
type Origin struct {
	Node          string `json:"node"` // text address, e.g. "1:0001.ABCD.1234"
	NodeID        uint32 `json:"node_id"`
	Authenticated bool   `json:"authenticated"` // proven via key exchange
	Trusted       bool   `json:"trusted"`       // in the handshake trust store
}

// Envelope is the single message shape on the wire. ReqID is set by the
// caller and echoed in the reply so a multiplexing client can match.
//
// AppID and ManifestVersion are set by the daemon when it bridges a call
// from one app to another — handlers can use them for the equivalent of
// `ipc.context()` (knowing who is calling, under which manifest_version).
// On a direct connection (no daemon in between) both fields are zero.
//
// Origin, when present, is the daemon-attested remote-node identity of
// the request — see the Origin doc for the trust model. It is only ever
// set by the trusted bridge path (CallWithOrigin); the broker never
// propagates it on cross-app calls.
type Envelope struct {
	Type            EnvelopeType    `json:"type"`
	ReqID           string          `json:"req_id"`
	Method          string          `json:"method,omitempty"`
	AppID           string          `json:"app_id,omitempty"`
	ManifestVersion int             `json:"manifest_version,omitempty"`
	Origin          *Origin         `json:"origin,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	Error           string          `json:"error,omitempty"`
}
