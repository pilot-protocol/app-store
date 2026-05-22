package payment

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Escrow holds a symmetric key K bound to a Contract, releasing it
// when presented with a verified Receipt. The platform's send-side
// paywall flow uses Hold to stash K right after encrypting the body;
// the receive-side redeem flow uses Redeem to swap a Receipt for K.
//
// Implementations: io.pilot.wallet/escrow-v1 (sender-self, the wallet
// holds K in its own memory + ledger); io.pilot.notary/v1 (always-on
// third-party); io.pilot.timelock/v1 (cryptographic, no online server).
type Escrow interface {
	ID() string
	Hold(ctx context.Context, c Contract, k []byte) (EscrowRef, error)
	Redeem(ctx context.Context, ref EscrowRef, r Receipt) ([]byte, error)
}

// ErrEscrowConsumed is returned by Redeem when the key has already
// been released. Stops replay against a single payment.
var ErrEscrowConsumed = errors.New("payment: escrow already consumed")

// ErrEscrowNotFound is returned by Redeem when the EscrowRef does not
// resolve to a held key.
var ErrEscrowNotFound = errors.New("payment: escrow not found")

// EscrowRegistry maps escrow ID → Escrow.
type EscrowRegistry struct {
	mu sync.RWMutex
	m  map[string]Escrow
}

// NewEscrowRegistry returns an empty registry.
func NewEscrowRegistry() *EscrowRegistry {
	return &EscrowRegistry{m: map[string]Escrow{}}
}

// Register adds an Escrow. Replaces any prior entry with the same ID.
func (r *EscrowRegistry) Register(e Escrow) error {
	if e == nil {
		return errors.New("payment: nil escrow")
	}
	id := e.ID()
	if id == "" {
		return errors.New("payment: escrow ID required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id] = e
	return nil
}

// Unregister removes an Escrow by ID. Idempotent.
func (r *EscrowRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
}

// Get returns the Escrow for id, or nil.
func (r *EscrowRegistry) Get(id string) Escrow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[id]
}

// IDs returns every registered escrow ID.
func (r *EscrowRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for id := range r.m {
		out = append(out, id)
	}
	return out
}

// PickFor returns an Escrow whose ID is in the contract's
// AcceptedEscrows (or any registered escrow when unconstrained). Used
// by the sender side to decide where to stash K. Returns the first
// match in map iteration order; callers wanting deterministic choice
// should constrain the contract.
func (r *EscrowRegistry) PickFor(c Contract) (Escrow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	accepted := acceptedSet(c.AcceptedEscrows)
	for id, e := range r.m {
		if accepted != nil && !accepted[id] {
			continue
		}
		return e, nil
	}
	return nil, fmt.Errorf("payment: no escrow matched accepted_escrows=%v", c.AcceptedEscrows)
}

// Redeem dispatches to the Escrow named by ref.EscrowID. The receipt
// must verify against the contract via the matching Method registry —
// callers chain Verify then Redeem to ensure key release is contingent
// on a real payment proof.
func (r *EscrowRegistry) Redeem(ctx context.Context, ref EscrowRef, rec Receipt) ([]byte, error) {
	r.mu.RLock()
	e, ok := r.m[ref.EscrowID]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("payment: escrow %q not registered", ref.EscrowID)
	}
	return e.Redeem(ctx, ref, rec)
}
