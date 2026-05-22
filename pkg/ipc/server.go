package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Handler is the server-side function that processes one request envelope.
// Return either (payload, nil) to send EnvReply, or (nil, err) to send
// EnvErr with err.Error() as the message.
//
// Handlers should not write to the conn directly — the Serve loop owns
// the write side. ctx may carry deadlines / cancellation set by Serve.
type Handler func(ctx context.Context, req *Envelope) (json.RawMessage, error)

// Dispatcher routes method names to handlers. Build once at startup,
// register all methods, then hand to Serve. Safe to read after setup;
// not safe to mutate concurrently with Serve.
type Dispatcher struct {
	handlers map[string]Handler
}

// NewDispatcher returns an empty Dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{handlers: map[string]Handler{}}
}

// Register binds method → handler. A second Register for the same method
// replaces the first (caller's responsibility to not do that by accident).
func (d *Dispatcher) Register(method string, h Handler) {
	d.handlers[method] = h
}

// Methods returns the registered method names (for inspection / logging).
func (d *Dispatcher) Methods() []string {
	out := make([]string, 0, len(d.handlers))
	for m := range d.handlers {
		out = append(out, m)
	}
	return out
}

// ErrMethodNotFound is returned to a caller when no handler is registered
// for the requested method.
var ErrMethodNotFound = errors.New("method not found")

// Serve reads envelopes from conn in a loop, dispatches each request to
// the matching handler, and writes the reply. Returns nil on clean EOF
// (peer closed gracefully between frames) or a non-nil error otherwise.
//
// Single-threaded: one request at a time per connection. If multiple
// goroutines need to share a connection on the caller side, they must
// coordinate write order outside this package. For higher fan-out, the
// daemon opens one Serve per connection in its own goroutine.
func Serve(ctx context.Context, conn io.ReadWriter, d *Dispatcher) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := ReadFrame(conn)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ipc serve: read: %w", err)
		}
		if req.Type != EnvReq {
			// Reply-shaped envelope arrived where a request was expected.
			// Skip silently — the peer may be confused but we don't want
			// to amplify by replying.
			continue
		}

		reply := dispatchOne(ctx, d, req)
		if err := WriteFrame(conn, reply); err != nil {
			return fmt.Errorf("ipc serve: write: %w", err)
		}
	}
}

func dispatchOne(ctx context.Context, d *Dispatcher, req *Envelope) *Envelope {
	h, ok := d.handlers[req.Method]
	if !ok {
		return &Envelope{Type: EnvErr, ReqID: req.ReqID, Error: ErrMethodNotFound.Error() + ": " + req.Method}
	}
	payload, err := h(ctx, req)
	if err != nil {
		return &Envelope{Type: EnvErr, ReqID: req.ReqID, Error: err.Error()}
	}
	return &Envelope{Type: EnvReply, ReqID: req.ReqID, Payload: payload}
}
