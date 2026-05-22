package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRoundtrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	d := NewDispatcher()
	d.Register("echo", func(ctx context.Context, req *Envelope) (json.RawMessage, error) {
		return req.Payload, nil
	})
	d.Register("boom", func(ctx context.Context, req *Envelope) (json.RawMessage, error) {
		return nil, errors.New("intentional failure")
	})

	go func() { _ = Serve(context.Background(), s, d) }()

	var out struct {
		Hello string `json:"hello"`
	}
	if err := Call(c, "echo", map[string]string{"hello": "world"}, &out); err != nil {
		t.Fatalf("echo call: %v", err)
	}
	if out.Hello != "world" {
		t.Errorf("got %q, want %q", out.Hello, "world")
	}

	err := Call(c, "boom", nil, nil)
	var srvErr *ErrServerError
	if !errors.As(err, &srvErr) || !strings.Contains(srvErr.Msg, "intentional failure") {
		t.Errorf("want server error 'intentional failure', got %v", err)
	}

	err = Call(c, "no-such-method", nil, nil)
	if !errors.As(err, &srvErr) || !strings.Contains(srvErr.Msg, "method not found") {
		t.Errorf("want method-not-found, got %v", err)
	}
}

func TestFrameTooLarge(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	// Server side: receive once, return whatever.
	go func() { _, _ = ReadFrame(s) }()

	huge := strings.Repeat("x", MaxFrameSize+1)
	env := &Envelope{Type: EnvReq, ReqID: "x", Method: "m", Payload: json.RawMessage(`"` + huge + `"`)}
	if err := WriteFrame(c, env); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestServerEOFOnClientClose(t *testing.T) {
	c, s := net.Pipe()

	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), s, NewDispatcher()) }()

	if err := c.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve should return nil on clean close, got %v", err)
		}
	case <-time.After(time.Second):
		t.Errorf("Serve did not return after client close")
	}
	_ = s.Close()
}
