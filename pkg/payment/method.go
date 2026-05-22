package payment

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Method produces and verifies proofs-of-payment for a Contract.
// Implementations are concrete payment rails — internal-ledger
// (io.pilot.wallet/v1), on-chain (io.lightning.bolt12/v1, etc.),
// off-chain (io.stripe.checkout/v1). Apps register their Methods at
// app-start with MethodRegistry.
//
// Implementations MUST be safe for concurrent use — the daemon may
// dispatch many Satisfies in parallel.
type Method interface {
	// ID is a globally unique identifier for this payment rail and
	// receipt format. The receiver of a Receipt uses MethodID to find
	// the matching Method's Verify.
	ID() string

	// Satisfy attempts to produce a Receipt for the Contract. It may
	// debit a balance, submit an on-chain tx, charge a card —
	// implementation-specific. Returns ErrCannotSatisfy if the contract
	// names assets/amounts the method does not support; a different
	// error for failures during a satisfaction attempt that's
	// otherwise in-scope.
	Satisfy(ctx context.Context, c Contract) (Receipt, error)

	// Verify checks a Receipt against its Contract. Returns nil if the
	// Receipt is a valid proof of payment. Verifiers are pure functions
	// of (Contract, Receipt) + the method's stable verification keyset;
	// they do not need to talk to the payer.
	Verify(ctx context.Context, c Contract, r Receipt) error
}

// ErrCannotSatisfy signals a method declines a contract because it is
// out-of-scope (wrong asset, unsupported amount, etc.). Distinct from
// transient failures, so the daemon's broker can try another method
// without surfacing the error to the user.
var ErrCannotSatisfy = errors.New("payment: method cannot satisfy contract")

// ErrUnknownMethod is returned by VerifierFor when no Method matches.
var ErrUnknownMethod = errors.New("payment: unknown method id")

// MethodRegistry maps method ID → Method. Populated at app-start, read
// during dispatch.
type MethodRegistry struct {
	mu sync.RWMutex
	m  map[string]Method
}

// NewMethodRegistry returns an empty registry.
func NewMethodRegistry() *MethodRegistry {
	return &MethodRegistry{m: map[string]Method{}}
}

// Register adds a Method. Replaces any prior entry with the same ID
// (later install wins); callers wanting strict-no-replace should
// check Has first.
func (r *MethodRegistry) Register(m Method) error {
	if m == nil {
		return errors.New("payment: nil method")
	}
	id := m.ID()
	if id == "" {
		return errors.New("payment: method ID required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id] = m
	return nil
}

// Unregister removes a Method by ID. Idempotent.
func (r *MethodRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
}

// Has reports whether id is registered.
func (r *MethodRegistry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.m[id]
	return ok
}

// Get returns the Method for id, or nil if absent.
func (r *MethodRegistry) Get(id string) Method {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[id]
}

// IDs returns every registered method ID.
func (r *MethodRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for id := range r.m {
		out = append(out, id)
	}
	return out
}

// Satisfy is the broker entry point on the payer side. Picks any
// registered Method whose ID is in c.AcceptedMethods (or any
// registered method, if the contract leaves it unconstrained) and
// asks it to Satisfy. Tries methods in registration order; returns
// the first Receipt produced. If every method returns
// ErrCannotSatisfy, returns the last such error.
func (r *MethodRegistry) Satisfy(ctx context.Context, c Contract) (Receipt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	accepted := acceptedSet(c.AcceptedMethods)
	var lastCannot error
	for id, m := range r.m {
		if accepted != nil && !accepted[id] {
			continue
		}
		receipt, err := m.Satisfy(ctx, c)
		if err == nil {
			return receipt, nil
		}
		if errors.Is(err, ErrCannotSatisfy) {
			lastCannot = err
			continue
		}
		return Receipt{}, fmt.Errorf("method %s: %w", id, err)
	}
	if lastCannot != nil {
		return Receipt{}, lastCannot
	}
	return Receipt{}, fmt.Errorf("payment: no method matched accepted_methods=%v", c.AcceptedMethods)
}

// Verify dispatches to the Method named by r.MethodID. The contract
// is passed so the method can re-derive canonical signing bytes,
// check the receipt is not replayed, etc.
func (r *MethodRegistry) Verify(ctx context.Context, c Contract, rec Receipt) error {
	r.mu.RLock()
	m, ok := r.m[rec.MethodID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownMethod, rec.MethodID)
	}
	return m.Verify(ctx, c, rec)
}

// acceptedSet returns nil if the contract accepts any method,
// otherwise a lookup set of accepted ids.
func acceptedSet(ids []string) map[string]bool {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
