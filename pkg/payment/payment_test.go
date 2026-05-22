package payment

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// ── Seal ────────────────────────────────────────────────────────────────

func TestDefaultSealRoundtrip(t *testing.T) {
	s := DefaultSeal()
	if s.ID() != DefaultSealID {
		t.Errorf("ID: %q, want %q", s.ID(), DefaultSealID)
	}
	key, err := RandomKey(s)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := RandomNonce(s)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello, paywalled world")
	ad := []byte("contract-id=abc")

	ct, err := s.Encrypt(plaintext, key, nonce, ad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := s.Decrypt(ct, key, nonce, ad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestSealRejectsTamperedAD(t *testing.T) {
	s := DefaultSeal()
	key, _ := RandomKey(s)
	nonce, _ := RandomNonce(s)
	ct, _ := s.Encrypt([]byte("secret"), key, nonce, []byte("ad-original"))
	if _, err := s.Decrypt(ct, key, nonce, []byte("ad-tampered")); err == nil {
		t.Error("AEAD should reject tampered AD")
	}
}

func TestSealRejectsTamperedCiphertext(t *testing.T) {
	s := DefaultSeal()
	key, _ := RandomKey(s)
	nonce, _ := RandomNonce(s)
	ct, _ := s.Encrypt([]byte("secret"), key, nonce, nil)
	ct[0] ^= 0xFF
	if _, err := s.Decrypt(ct, key, nonce, nil); err == nil {
		t.Error("AEAD should reject tampered ciphertext")
	}
}

func TestSealRegistryHasDefault(t *testing.T) {
	r := NewSealRegistry()
	if got := r.Get(DefaultSealID); got == nil {
		t.Error("registry missing default seal")
	}
}

// ── MethodRegistry ──────────────────────────────────────────────────────

type stubMethod struct {
	id        string
	satisfies bool
	verified  func(Contract, Receipt) error
}

func (m *stubMethod) ID() string { return m.id }
func (m *stubMethod) Satisfy(_ context.Context, c Contract) (Receipt, error) {
	if !m.satisfies {
		return Receipt{}, ErrCannotSatisfy
	}
	return Receipt{ContractID: c.ID, MethodID: m.id, Payload: []byte("ok")}, nil
}
func (m *stubMethod) Verify(_ context.Context, c Contract, r Receipt) error {
	if m.verified != nil {
		return m.verified(c, r)
	}
	if r.MethodID != m.id {
		return errors.New("wrong method")
	}
	return nil
}

func TestMethodRegistryRoutesByAcceptedMethods(t *testing.T) {
	mr := NewMethodRegistry()
	_ = mr.Register(&stubMethod{id: "io.a/v1", satisfies: true})
	_ = mr.Register(&stubMethod{id: "io.b/v1", satisfies: true})

	c := Contract{ID: "c1", AcceptedMethods: []string{"io.b/v1"}}
	r, err := mr.Satisfy(context.Background(), c)
	if err != nil {
		t.Fatalf("satisfy: %v", err)
	}
	if r.MethodID != "io.b/v1" {
		t.Errorf("picked method: %q, want io.b/v1", r.MethodID)
	}
}

func TestMethodRegistrySatisfyFallsThroughCannotSatisfy(t *testing.T) {
	mr := NewMethodRegistry()
	_ = mr.Register(&stubMethod{id: "io.a/v1", satisfies: false})
	_ = mr.Register(&stubMethod{id: "io.b/v1", satisfies: true})

	r, err := mr.Satisfy(context.Background(), Contract{ID: "c"})
	if err != nil {
		t.Fatalf("satisfy: %v", err)
	}
	if r.MethodID != "io.b/v1" {
		t.Errorf("fall-through method: %q, want io.b/v1", r.MethodID)
	}
}

func TestMethodRegistrySatisfyAllCannotSatisfy(t *testing.T) {
	mr := NewMethodRegistry()
	_ = mr.Register(&stubMethod{id: "io.a/v1", satisfies: false})
	_, err := mr.Satisfy(context.Background(), Contract{ID: "c"})
	if !errors.Is(err, ErrCannotSatisfy) {
		t.Errorf("want ErrCannotSatisfy, got %v", err)
	}
}

func TestMethodRegistryVerifyDispatch(t *testing.T) {
	mr := NewMethodRegistry()
	called := false
	_ = mr.Register(&stubMethod{
		id: "io.x/v1",
		verified: func(Contract, Receipt) error {
			called = true
			return nil
		},
	})
	err := mr.Verify(context.Background(), Contract{ID: "c"}, Receipt{MethodID: "io.x/v1"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !called {
		t.Error("Verify did not dispatch to the method")
	}
}

func TestMethodRegistryVerifyUnknown(t *testing.T) {
	mr := NewMethodRegistry()
	err := mr.Verify(context.Background(), Contract{}, Receipt{MethodID: "no.such/v1"})
	if !errors.Is(err, ErrUnknownMethod) {
		t.Errorf("want ErrUnknownMethod, got %v", err)
	}
}

// ── EscrowRegistry ──────────────────────────────────────────────────────

type stubEscrow struct {
	id   string
	keys map[string][]byte // contract_id → K
}

func newStubEscrow(id string) *stubEscrow { return &stubEscrow{id: id, keys: map[string][]byte{}} }
func (e *stubEscrow) ID() string          { return e.id }
func (e *stubEscrow) Hold(_ context.Context, c Contract, k []byte) (EscrowRef, error) {
	e.keys[c.ID] = k
	return EscrowRef{EscrowID: e.id, ContractID: c.ID, Token: c.ID}, nil
}
func (e *stubEscrow) Redeem(_ context.Context, ref EscrowRef, _ Receipt) ([]byte, error) {
	k, ok := e.keys[ref.ContractID]
	if !ok {
		return nil, ErrEscrowNotFound
	}
	delete(e.keys, ref.ContractID)
	return k, nil
}

func TestEscrowRegistryPickFor(t *testing.T) {
	er := NewEscrowRegistry()
	_ = er.Register(newStubEscrow("io.wallet/escrow-v1"))
	_ = er.Register(newStubEscrow("io.notary/v1"))

	e, err := er.PickFor(Contract{AcceptedEscrows: []string{"io.notary/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.ID() != "io.notary/v1" {
		t.Errorf("picked: %q, want io.notary/v1", e.ID())
	}
}

func TestEscrowRegistryRedeemRoundtrip(t *testing.T) {
	er := NewEscrowRegistry()
	e := newStubEscrow("io.wallet/escrow-v1")
	_ = er.Register(e)

	c := Contract{ID: "c1", ExpiresAt: time.Now().Add(time.Hour)}
	ref, err := e.Hold(context.Background(), c, []byte("super-secret-key"))
	if err != nil {
		t.Fatal(err)
	}

	k, err := er.Redeem(context.Background(), ref, Receipt{ContractID: "c1"})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if string(k) != "super-secret-key" {
		t.Errorf("redeemed key wrong: %q", k)
	}

	// Second redeem returns not-found (stub removed on first).
	if _, err := er.Redeem(context.Background(), ref, Receipt{ContractID: "c1"}); err == nil {
		t.Error("expected error on second redeem")
	}
}

func TestEscrowRegistryRedeemUnknown(t *testing.T) {
	er := NewEscrowRegistry()
	_, err := er.Redeem(context.Background(), EscrowRef{EscrowID: "missing"}, Receipt{})
	if err == nil {
		t.Error("expected error for unknown escrow ID")
	}
}
