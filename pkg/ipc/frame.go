package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize bounds any single envelope. Defends against a malicious or
// runaway peer that tries to allocate gigabytes by sending a giant
// length prefix. 1 MiB is comfortably larger than any wallet IPC reply
// (the biggest is a paginated history slice).
const MaxFrameSize = 1 << 20

// ErrFrameTooLarge is returned by ReadFrame when the length prefix
// exceeds MaxFrameSize. The connection should be dropped.
var ErrFrameTooLarge = errors.New("ipc: frame exceeds max size")

// WriteFrame serializes env as JSON and writes it as a 4-byte BE length
// prefix followed by the JSON bytes. Safe to call from one goroutine; not
// safe to call concurrently on the same writer (no internal locking).
func WriteFrame(w io.Writer, env *Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("ipc: marshal envelope: %w", err)
	}
	if len(body) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("ipc: write length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("ipc: write body: %w", err)
	}
	return nil
}

// ReadFrame reads one envelope from r. Returns io.EOF cleanly when the
// peer closes between frames. Any partial-frame condition is returned
// as a non-EOF error.
func ReadFrame(r io.Reader) (*Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// io.EOF on a clean boundary surfaces directly; partial reads
		// become io.ErrUnexpectedEOF which is *not* a clean shutdown.
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("ipc: zero-length frame")
	}
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("ipc: read body: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("ipc: unmarshal envelope: %w", err)
	}
	return &env, nil
}
