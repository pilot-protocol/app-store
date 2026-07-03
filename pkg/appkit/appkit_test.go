package appkit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// okHandler returns "ok" and records the envelope it was invoked with.
func okHandler(got **ipc.Envelope) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		if got != nil {
			*got = req
		}
		return json.RawMessage(`"ok"`), nil
	}
}

func reqWithOrigin(o *ipc.Origin) *ipc.Envelope {
	return &ipc.Envelope{Type: ipc.EnvReq, ReqID: "r", Method: "m", Origin: o}
}

func TestRequireOrigin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name   string
		origin *ipc.Origin
		wantOK bool
	}{
		{"nil origin rejected", nil, false},
		{"unauthenticated origin rejected", &ipc.Origin{Node: "1:0001.0000.0001", NodeID: 1}, false},
		{"authenticated origin passes", &ipc.Origin{Node: "1:0001.0000.0001", NodeID: 1, Authenticated: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireOrigin(okHandler(nil))
			_, err := h(ctx, reqWithOrigin(tc.origin))
			if tc.wantOK && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !tc.wantOK && !errors.Is(err, ErrOriginRequired) {
				t.Fatalf("err = %v, want ErrOriginRequired", err)
			}
		})
	}
}

func TestLimitPerNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := PerNodeLimiter(2, time.Minute)
	h := LimitPerNode(l, okHandler(nil))

	a := &ipc.Origin{Node: "1:0001.0000.000A", NodeID: 10, Authenticated: true}
	b := &ipc.Origin{Node: "1:0001.0000.000B", NodeID: 11, Authenticated: true}

	for i := 0; i < 2; i++ {
		if _, err := h(ctx, reqWithOrigin(a)); err != nil {
			t.Fatalf("request %d from a: %v", i+1, err)
		}
	}
	if _, err := h(ctx, reqWithOrigin(a)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	// Budget is per node identity — b is unaffected by a's exhaustion.
	if _, err := h(ctx, reqWithOrigin(b)); err != nil {
		t.Fatalf("request from b: %v", err)
	}
	// Defensive: no origin → nothing to key on → rejected, not pooled.
	if _, err := h(ctx, reqWithOrigin(nil)); !errors.Is(err, ErrOriginRequired) {
		t.Fatalf("err = %v, want ErrOriginRequired", err)
	}
}

func TestRequireEnvelope_ValidSynthesizesOrigin(t *testing.T) {
	t.Parallel()
	verify := func(envelope, signature string) (VerifyResult, error) {
		if envelope != "env-blob" || signature != "sig-blob" {
			t.Errorf("verify called with (%q, %q)", envelope, signature)
		}
		return VerifyResult{
			Valid:         true,
			Node:          "1:0001.ABCD.1234",
			NodeID:        77,
			Authenticated: true,
			Trusted:       true,
			Online:        true,
		}, nil
	}
	var got *ipc.Envelope
	h := RequireEnvelope(verify, okHandler(&got))

	req := &ipc.Envelope{
		Type:    ipc.EnvReq,
		ReqID:   "r",
		Method:  "m",
		Payload: json.RawMessage(`{"pilot_envelope":"env-blob","pilot_signature":"sig-blob","extra":1}`),
	}
	if _, err := h(context.Background(), req); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got == nil || got.Origin == nil {
		t.Fatal("handler did not receive a synthesized origin")
	}
	want := ipc.Origin{Node: "1:0001.ABCD.1234", NodeID: 77, Authenticated: true, Trusted: true}
	if *got.Origin != want {
		t.Errorf("origin = %+v, want %+v", *got.Origin, want)
	}
	// The caller's envelope must not be mutated.
	if req.Origin != nil {
		t.Error("RequireEnvelope mutated the caller's envelope")
	}
}

func TestRequireEnvelope_Rejections(t *testing.T) {
	t.Parallel()
	neverVerify := func(string, string) (VerifyResult, error) {
		t.Error("verify must not run for malformed payloads")
		return VerifyResult{}, nil
	}

	cases := []struct {
		name    string
		payload string
	}{
		{"empty payload", ""},
		{"not json", `{{{`},
		{"json but wrong shape", `[1,2,3]`},
		{"neither field", `{"other":"x"}`},
		{"missing signature", `{"pilot_envelope":"e"}`},
		{"missing envelope", `{"pilot_signature":"s"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireEnvelope(neverVerify, okHandler(nil))
			req := &ipc.Envelope{Type: ipc.EnvReq, ReqID: "r", Method: "m"}
			if tc.payload != "" {
				req.Payload = json.RawMessage(tc.payload)
			}
			_, err := h(context.Background(), req)
			if !errors.Is(err, ErrEnvelopeRequired) {
				t.Fatalf("err = %v, want ErrEnvelopeRequired", err)
			}
		})
	}
}

func TestRequireEnvelope_InvalidAndErrorResults(t *testing.T) {
	t.Parallel()
	payload := json.RawMessage(`{"pilot_envelope":"e","pilot_signature":"s"}`)

	t.Run("verify says not valid", func(t *testing.T) {
		h := RequireEnvelope(func(string, string) (VerifyResult, error) {
			return VerifyResult{Valid: false}, nil
		}, okHandler(nil))
		_, err := h(context.Background(), &ipc.Envelope{Type: ipc.EnvReq, Payload: payload})
		if !errors.Is(err, ErrEnvelopeInvalid) {
			t.Fatalf("err = %v, want ErrEnvelopeInvalid", err)
		}
	})

	t.Run("verify transport error propagates", func(t *testing.T) {
		boom := errors.New("daemon unreachable")
		h := RequireEnvelope(func(string, string) (VerifyResult, error) {
			return VerifyResult{}, boom
		}, okHandler(nil))
		_, err := h(context.Background(), &ipc.Envelope{Type: ipc.EnvReq, Payload: payload})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want wrapped %v", err, boom)
		}
	})
}

// TestComposedChain wires the intended stack — RequireOrigin →
// LimitPerNode → handler — and drives it as one unit.
func TestComposedChain(t *testing.T) {
	t.Parallel()
	l := PerNodeLimiter(1, time.Minute)
	h := RequireOrigin(LimitPerNode(l, okHandler(nil)))
	ctx := context.Background()

	if _, err := h(ctx, reqWithOrigin(nil)); !errors.Is(err, ErrOriginRequired) {
		t.Fatalf("err = %v, want ErrOriginRequired", err)
	}
	o := &ipc.Origin{Node: "1:0001.0000.0001", NodeID: 1, Authenticated: true}
	if _, err := h(ctx, reqWithOrigin(o)); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := h(ctx, reqWithOrigin(o)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}
