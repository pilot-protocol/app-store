package ipc

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestOrigin_JSONRoundTrip serializes an envelope carrying a full Origin
// block and reads it back — every field must survive the wire.
func TestOrigin_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	in := &Envelope{
		Type:   EnvReq,
		ReqID:  "r1",
		Method: "pay",
		Origin: &Origin{
			Node:          "1:0001.ABCD.1234",
			NodeID:        0xABCD1234,
			Authenticated: true,
			Trusted:       true,
		},
		Payload: json.RawMessage(`{"amount":5}`),
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Envelope
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Origin == nil {
		t.Fatal("origin lost in round trip")
	}
	if *out.Origin != *in.Origin {
		t.Errorf("origin = %+v, want %+v", *out.Origin, *in.Origin)
	}
}

// TestOrigin_OmittedWhenNil asserts the omitempty contract: an envelope
// without an origin must not emit an "origin" key at all, so pre-origin
// peers see byte-identical wire shapes.
func TestOrigin_OmittedWhenNil(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(&Envelope{Type: EnvReq, ReqID: "r2", Method: "ping"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("origin")) {
		t.Errorf("nil origin must be omitted, got %s", raw)
	}
}

// TestOrigin_FrameRoundTrip pushes an origin-bearing envelope through the
// actual length-prefixed framing layer.
func TestOrigin_FrameRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	in := &Envelope{
		Type:   EnvReq,
		ReqID:  "r3",
		Method: "ping",
		Origin: &Origin{Node: "1:0001.0000.0007", NodeID: 7, Authenticated: true},
	}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if out.Origin == nil || *out.Origin != *in.Origin {
		t.Errorf("origin = %+v, want %+v", out.Origin, in.Origin)
	}
}
