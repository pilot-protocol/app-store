package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// shortReader exposes io.EOF on the very first read, simulating a peer
// that closed the connection cleanly between frames.
type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// TestReadFrame_EOFOnHeader covers the clean-EOF branch.
func TestReadFrame_EOFOnHeader(t *testing.T) {
	t.Parallel()
	_, err := ReadFrame(eofReader{})
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

// TestReadFrame_PartialHeaderIsUnexpectedEOF covers the io.ReadFull
// partial-read error path on the header.
func TestReadFrame_PartialHeaderIsUnexpectedEOF(t *testing.T) {
	t.Parallel()
	r := bytes.NewReader([]byte{0x00, 0x00}) // only 2 of 4 header bytes
	_, err := ReadFrame(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestReadFrame_ZeroLengthRejected covers the explicit zero-length
// branch.
func TestReadFrame_ZeroLengthRejected(t *testing.T) {
	t.Parallel()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0)
	_, err := ReadFrame(bytes.NewReader(hdr))
	if err == nil || !strings.Contains(err.Error(), "zero-length") {
		t.Errorf("err = %v, want zero-length error", err)
	}
}

// TestReadFrame_OversizedRejected covers the MaxFrameSize branch.
func TestReadFrame_OversizedRejected(t *testing.T) {
	t.Parallel()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(MaxFrameSize+1))
	_, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("err = %v, want ErrFrameTooLarge", err)
	}
}

// TestReadFrame_PartialBodyIsError covers the partial-body branch.
func TestReadFrame_PartialBodyIsError(t *testing.T) {
	t.Parallel()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 100) // promise 100 bytes, supply 5
	buf := append(hdr, []byte("short")...)
	_, err := ReadFrame(bytes.NewReader(buf))
	if err == nil || !strings.Contains(err.Error(), "read body") {
		t.Errorf("err = %v, want read body error", err)
	}
}

// TestReadFrame_BadJSONBody covers the json.Unmarshal branch.
func TestReadFrame_BadJSONBody(t *testing.T) {
	t.Parallel()
	hdr := make([]byte, 4)
	body := []byte("not-json")
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	buf := append(hdr, body...)
	_, err := ReadFrame(bytes.NewReader(buf))
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("err = %v, want unmarshal error", err)
	}
}

// errWriter fails after a configurable number of bytes.
type errWriter struct {
	max    int
	called int
}

func (w *errWriter) Write(p []byte) (int, error) {
	w.called++
	if w.called > w.max {
		return 0, errors.New("write boom")
	}
	return len(p), nil
}

// TestWriteFrame_HeaderWriteFails covers the "write length: ..." branch.
func TestWriteFrame_HeaderWriteFails(t *testing.T) {
	t.Parallel()
	w := &errWriter{max: 0}
	env := &Envelope{Type: EnvReq, ReqID: "x", Method: "m"}
	err := WriteFrame(w, env)
	if err == nil || !strings.Contains(err.Error(), "write length") {
		t.Errorf("err = %v, want write length error", err)
	}
}

// TestWriteFrame_BodyWriteFails covers the "write body: ..." branch
// (header write succeeds, body write fails).
func TestWriteFrame_BodyWriteFails(t *testing.T) {
	t.Parallel()
	w := &errWriter{max: 1}
	env := &Envelope{Type: EnvReq, ReqID: "x", Method: "m"}
	err := WriteFrame(w, env)
	if err == nil || !strings.Contains(err.Error(), "write body") {
		t.Errorf("err = %v, want write body error", err)
	}
}

// TestServe_NonReqEnvelopeSkipped wires a server, sends an envelope
// with type=reply, and confirms the server keeps reading instead of
// replying — covers the type-mismatch silent-skip branch in Serve.
func TestServe_NonReqEnvelopeSkipped(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	d := NewDispatcher()
	d.Register("echo", func(_ context.Context, req *Envelope) (json.RawMessage, error) {
		return req.Payload, nil
	})

	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), s, d) }()

	// Send a reply-shaped envelope. The server skips it silently.
	wrong := &Envelope{Type: EnvReply, ReqID: "stale"}
	if err := WriteFrame(c, wrong); err != nil {
		t.Fatal(err)
	}
	// Now send a real request to confirm the loop kept running.
	var out json.RawMessage
	if err := Call(c, "echo", "hi", &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	_ = c.Close()
	<-done
}

// TestServe_ReturnsCtxError covers the ctx.Err early return path.
func TestServe_ReturnsCtxError(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before Serve loops

	if err := Serve(ctx, s, NewDispatcher()); err == nil {
		t.Error("Serve with canceled ctx should error")
	}
}

// TestServe_ReadErrorReturnsWrapped covers the non-EOF read-error branch.
func TestServe_ReadErrorReturnsWrapped(t *testing.T) {
	t.Parallel()
	// Half-write a header then close — the server will see ErrUnexpectedEOF.
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), s, NewDispatcher()) }()

	// Write a partial header (2 bytes) then close. This won't propagate to
	// the server-side ReadFull until the pipe is closed because pipes are
	// synchronous; instead, write a full header + truncated body to force
	// a "read body" error.
	body := []byte(`{"type":"req","req_id":"x"`) // truncated body — looks like header promises N bytes
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+50)) // promise more than we send
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.Write(append(hdr, body...))
		_ = c.Close()
	}()
	wg.Wait()

	err := <-done
	if err == nil {
		t.Error("Serve: expected non-nil error on partial body")
	}
}

// TestCall_RandReqIDWorksRepeatedly drives randReqID indirectly by
// issuing many Call invocations — confirms no rand-source exhaustion
// and the 100% branch coverage.
func TestCall_RandReqIDWorksRepeatedly(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	d := NewDispatcher()
	d.Register("noop", func(_ context.Context, _ *Envelope) (json.RawMessage, error) {
		return nil, nil
	})
	go func() { _ = Serve(context.Background(), s, d) }()

	for i := 0; i < 5; i++ {
		if err := Call(c, "noop", nil, nil); err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
}

// TestCall_ServerClosesBeforeReply covers the io.EOF → "server closed
// before reply" branch in Call. We swallow the request fully (so the
// write side succeeds), then close — Call's ReadFrame sees clean EOF.
func TestCall_ServerClosesBeforeReply(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()

	go func() {
		// Drain the full request frame (header + body) so the client's
		// WriteFrame can complete before we close.
		_, _ = ReadFrame(s)
		_ = s.Close()
	}()

	err := Call(c, "method", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "server closed") {
		t.Errorf("err = %v, want 'server closed before reply'", err)
	}
}

// TestCall_ReqIDMismatch covers the req_id mismatch branch.
func TestCall_ReqIDMismatch(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	// Server: read the request, send a reply with a DIFFERENT req_id.
	go func() {
		req, err := ReadFrame(s)
		if err != nil {
			return
		}
		_ = WriteFrame(s, &Envelope{
			Type:  EnvReply,
			ReqID: "mismatch-" + req.ReqID, // intentionally wrong
		})
	}()
	err := Call(c, "method", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "req_id mismatch") {
		t.Errorf("err = %v, want req_id mismatch", err)
	}
}

// TestCall_UnexpectedEnvelopeType covers the "default" branch in the
// reply switch.
func TestCall_UnexpectedEnvelopeType(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		req, err := ReadFrame(s)
		if err != nil {
			return
		}
		_ = WriteFrame(s, &Envelope{Type: "weird-type", ReqID: req.ReqID})
	}()
	err := Call(c, "method", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected envelope type") {
		t.Errorf("err = %v, want unexpected envelope type", err)
	}
}

// TestCall_BadResultUnmarshal covers the result-unmarshal error branch.
func TestCall_BadResultUnmarshal(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	d := NewDispatcher()
	d.Register("send", func(_ context.Context, _ *Envelope) (json.RawMessage, error) {
		return json.RawMessage(`"a string"`), nil
	})
	go func() { _ = Serve(context.Background(), s, d) }()

	var dst int // intentionally wrong type for a string payload
	err := Call(c, "send", nil, &dst)
	if err == nil || !strings.Contains(err.Error(), "unmarshal result") {
		t.Errorf("err = %v, want unmarshal result error", err)
	}
}

// TestCall_BadArgsMarshal covers the marshal-args error branch.
func TestCall_BadArgsMarshal(t *testing.T) {
	t.Parallel()
	c, _ := net.Pipe()
	defer c.Close()
	// json.Marshal of a channel returns an error.
	err := Call(c, "method", make(chan int), nil)
	if err == nil || !strings.Contains(err.Error(), "marshal args") {
		t.Errorf("err = %v, want marshal args error", err)
	}
}
