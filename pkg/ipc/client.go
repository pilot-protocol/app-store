package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrServerError wraps an EnvErr reply from the server side. Callers can
// `errors.As` to extract the wire-level error string.
type ErrServerError struct{ Msg string }

func (e *ErrServerError) Error() string { return "ipc: server error: " + e.Msg }

// Call sends one request envelope and waits for the matching reply on
// the same conn. Synchronous: callers must serialize concurrent Calls
// on a single conn (one in flight at a time).
//
// If args is nil, the request payload is empty. If result is nil, the
// reply payload is discarded. Both are otherwise json-marshaled /
// unmarshaled.
//
// Returns *ErrServerError on EnvErr replies, a wrapped framing error on
// transport failures, or nil on success.
func Call(conn io.ReadWriter, method string, args, result any) error {
	reqID, err := randReqID()
	if err != nil {
		return fmt.Errorf("ipc call: req_id: %w", err)
	}
	var payload json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("ipc call: marshal args: %w", err)
		}
		payload = b
	}
	req := &Envelope{
		Type:    EnvReq,
		ReqID:   reqID,
		Method:  method,
		Payload: payload,
	}
	if err := WriteFrame(conn, req); err != nil {
		return fmt.Errorf("ipc call: write: %w", err)
	}

	reply, err := ReadFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("ipc call: server closed before reply")
		}
		return fmt.Errorf("ipc call: read: %w", err)
	}
	if reply.ReqID != reqID {
		return fmt.Errorf("ipc call: req_id mismatch: got %q want %q", reply.ReqID, reqID)
	}
	switch reply.Type {
	case EnvErr:
		return &ErrServerError{Msg: reply.Error}
	case EnvReply:
		if result == nil || len(reply.Payload) == 0 {
			return nil
		}
		if err := json.Unmarshal(reply.Payload, result); err != nil {
			return fmt.Errorf("ipc call: unmarshal result: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("ipc call: unexpected envelope type %q", reply.Type)
	}
}

func randReqID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
