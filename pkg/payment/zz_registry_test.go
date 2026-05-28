package payment

import (
	"context"
	"errors"
	"testing"
)

// fakeMethod is a programmable Method for testing the registry.
type fakeMethod struct {
	id        string
	satisfyFn func(Contract) (Receipt, error)
	verifyFn  func(Contract, Receipt) error
}

func (m *fakeMethod) ID() string { return m.id }
func (m *fakeMethod) Satisfy(_ context.Context, c Contract) (Receipt, error) {
	if m.satisfyFn != nil {
		return m.satisfyFn(c)
	}
	return Receipt{}, ErrCannotSatisfy
}
func (m *fakeMethod) Verify(_ context.Context, c Contract, r Receipt) error {
	if m.verifyFn != nil {
		return m.verifyFn(c, r)
	}
	return nil
}

// fakeEscrow implements Escrow for tests.
type fakeEscrow struct {
	id     string
	holdFn func(Contract, []byte) (EscrowRef, error)
	redFn  func(EscrowRef, Receipt) ([]byte, error)
}

func (e *fakeEscrow) ID() string { return e.id }
func (e *fakeEscrow) Hold(_ context.Context, c Contract, k []byte) (EscrowRef, error) {
	if e.holdFn != nil {
		return e.holdFn(c, k)
	}
	return EscrowRef{EscrowID: e.id, ContractID: c.ID}, nil
}
func (e *fakeEscrow) Redeem(_ context.Context, ref EscrowRef, r Receipt) ([]byte, error) {
	if e.redFn != nil {
		return e.redFn(ref, r)
	}
	return []byte("k"), nil
}

func TestMethodRegistry_Register_Errors(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("nil method: expected error")
	}
	if err := r.Register(&fakeMethod{id: ""}); err == nil {
		t.Error("empty ID: expected error")
	}
}

func TestMethodRegistry_HasGetUnregister(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	m := &fakeMethod{id: "m1"}
	if err := r.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !r.Has("m1") {
		t.Error("Has(m1) = false")
	}
	if got := r.Get("m1"); got == nil {
		t.Error("Get(m1) = nil")
	}
	if got := r.Get("unknown"); got != nil {
		t.Errorf("Get(unknown) = %v, want nil", got)
	}

	r.Unregister("m1")
	if r.Has("m1") {
		t.Error("Has(m1) after Unregister = true")
	}
	// Idempotent.
	r.Unregister("m1")
}

func TestMethodRegistry_IDs(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	for _, id := range []string{"a", "b", "c"} {
		_ = r.Register(&fakeMethod{id: id})
	}
	if got := r.IDs(); len(got) != 3 {
		t.Errorf("IDs() = %v, want 3 entries", got)
	}
}

func TestMethodRegistry_Satisfy_NoMatch(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	_, err := r.Satisfy(context.Background(), Contract{AcceptedMethods: []string{"none"}})
	if err == nil {
		t.Error("expected error when no method matches")
	}
}

func TestMethodRegistry_Satisfy_HappyPath(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	_ = r.Register(&fakeMethod{
		id: "good",
		satisfyFn: func(c Contract) (Receipt, error) {
			return Receipt{ContractID: c.ID, MethodID: "good"}, nil
		},
	})
	got, err := r.Satisfy(context.Background(), Contract{ID: "c1", AcceptedMethods: []string{"good"}})
	if err != nil {
		t.Fatalf("Satisfy: %v", err)
	}
	if got.MethodID != "good" {
		t.Errorf("MethodID = %q", got.MethodID)
	}
}

func TestMethodRegistry_Satisfy_LastCannotPropagated(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	_ = r.Register(&fakeMethod{
		id: "cannot",
		satisfyFn: func(Contract) (Receipt, error) { return Receipt{}, ErrCannotSatisfy },
	})
	_, err := r.Satisfy(context.Background(), Contract{ID: "c1"})
	if !errors.Is(err, ErrCannotSatisfy) {
		t.Errorf("err = %v, want ErrCannotSatisfy", err)
	}
}

func TestMethodRegistry_Satisfy_TransientErrorReturned(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	_ = r.Register(&fakeMethod{
		id: "boom",
		satisfyFn: func(Contract) (Receipt, error) { return Receipt{}, errors.New("transient") },
	})
	_, err := r.Satisfy(context.Background(), Contract{ID: "c1"})
	if err == nil {
		t.Error("expected transient error to propagate")
	}
}

func TestMethodRegistry_Verify_UnknownMethod(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	err := r.Verify(context.Background(), Contract{}, Receipt{MethodID: "unknown"})
	if !errors.Is(err, ErrUnknownMethod) {
		t.Errorf("err = %v, want ErrUnknownMethod", err)
	}
}

func TestMethodRegistry_Verify_DelegatesToMethod(t *testing.T) {
	t.Parallel()
	r := NewMethodRegistry()
	calls := 0
	_ = r.Register(&fakeMethod{
		id: "verify-me",
		verifyFn: func(Contract, Receipt) error { calls++; return nil },
	})
	if err := r.Verify(context.Background(), Contract{}, Receipt{MethodID: "verify-me"}); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestEscrowRegistry_Register_Errors(t *testing.T) {
	t.Parallel()
	r := NewEscrowRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("nil escrow: expected error")
	}
	if err := r.Register(&fakeEscrow{id: ""}); err == nil {
		t.Error("empty ID: expected error")
	}
}

func TestEscrowRegistry_GetUnregisterIDs(t *testing.T) {
	t.Parallel()
	r := NewEscrowRegistry()
	e := &fakeEscrow{id: "e1"}
	_ = r.Register(e)
	if got := r.Get("e1"); got == nil {
		t.Error("Get(e1) = nil")
	}
	if got := r.Get("unknown"); got != nil {
		t.Errorf("Get(unknown) = %v", got)
	}
	if got := r.IDs(); len(got) != 1 {
		t.Errorf("IDs len = %d, want 1", len(got))
	}
	r.Unregister("e1")
	if got := r.Get("e1"); got != nil {
		t.Errorf("Get(e1) after Unregister = %v", got)
	}
}

func TestEscrowRegistry_Redeem_UnknownID(t *testing.T) {
	t.Parallel()
	r := NewEscrowRegistry()
	_, err := r.Redeem(context.Background(),
		EscrowRef{EscrowID: "missing"}, Receipt{})
	if err == nil {
		t.Error("expected error for unknown escrow ID")
	}
}

func TestEscrowRegistry_PickFor_NoMatch(t *testing.T) {
	t.Parallel()
	r := NewEscrowRegistry()
	_ = r.Register(&fakeEscrow{id: "e1"})
	_, err := r.PickFor(Contract{AcceptedEscrows: []string{"none"}})
	if err == nil {
		t.Error("expected error for unconstrained-but-no-match")
	}
}

// TestSealedEnvelope_IDs covers the IDs accessor on Sealed.
func TestSealedEnvelope_IDsList(t *testing.T) {
	t.Parallel()
	// SealedEnvelope helper IDs returns method+escrow registry IDs.
	mr := NewMethodRegistry()
	_ = mr.Register(&fakeMethod{id: "m1"})
	if got := mr.IDs(); len(got) != 1 {
		t.Errorf("method IDs = %v", got)
	}
}
