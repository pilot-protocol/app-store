package payment

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Seal is the symmetric encryption primitive for paywalled message
// bodies. The default impl (DefaultSeal) is chacha20-poly1305 with the
// standard 12-byte nonce; apps may register others (e.g. age x25519 for
// recipient-targeted encryption) and the contract names the algorithm
// via SealID so verification picks the right impl.
//
// Encrypt/Decrypt both take associated data (AD) that's authenticated
// but not encrypted. Callers pass the canonical SealedEnvelope header
// (or a binding of it) as AD so a tampered Contract/EscrowRef triggers
// an AEAD failure instead of producing a valid plaintext under
// rewritten metadata.
type Seal interface {
	ID() string
	KeySize() int
	NonceSize() int
	Encrypt(plaintext, key, nonce, ad []byte) ([]byte, error)
	Decrypt(ciphertext, key, nonce, ad []byte) ([]byte, error)
}

// DefaultSeal returns the chacha20-poly1305 implementation. ID is
// "seal/chacha20-poly1305-v1".
func DefaultSeal() Seal { return chachaSeal{} }

const DefaultSealID = "seal/chacha20-poly1305-v1"

type chachaSeal struct{}

func (chachaSeal) ID() string     { return DefaultSealID }
func (chachaSeal) KeySize() int   { return chacha20poly1305.KeySize }
func (chachaSeal) NonceSize() int { return chacha20poly1305.NonceSize }

func (chachaSeal) Encrypt(plaintext, key, nonce, ad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("seal: new aead: %w", err)
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("seal: nonce size %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Seal(nil, nonce, plaintext, ad), nil
}

func (chachaSeal) Decrypt(ciphertext, key, nonce, ad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("seal: new aead: %w", err)
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("seal: nonce size %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Open(nil, nonce, ciphertext, ad)
}

// SealRegistry maps seal ID → Seal.
type SealRegistry struct {
	mu sync.RWMutex
	m  map[string]Seal
}

// NewSealRegistry returns a registry pre-populated with DefaultSeal.
// Apps that ship alternate seals call Register at app-start.
func NewSealRegistry() *SealRegistry {
	r := &SealRegistry{m: map[string]Seal{}}
	_ = r.Register(DefaultSeal())
	return r
}

func (r *SealRegistry) Register(s Seal) error {
	if s == nil {
		return errors.New("payment: nil seal")
	}
	id := s.ID()
	if id == "" {
		return errors.New("payment: seal ID required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id] = s
	return nil
}

func (r *SealRegistry) Get(id string) Seal {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[id]
}

func (r *SealRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for id := range r.m {
		out = append(out, id)
	}
	return out
}

// RandomKey returns a cryptographically random key of the right size
// for seal. Convenience for callers wrapping a body before sealing.
func RandomKey(seal Seal) ([]byte, error) {
	k := make([]byte, seal.KeySize())
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("seal: random key: %w", err)
	}
	return k, nil
}

// RandomNonce returns a cryptographically random nonce of the right
// size for seal. For chacha20-poly1305 the 12-byte nonce is safe to
// pick randomly — collision probability is ~2^-32 after 2^32 messages
// under one key, but we use fresh keys per envelope, so reuse is
// effectively impossible.
func RandomNonce(seal Seal) ([]byte, error) {
	n := make([]byte, seal.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("seal: random nonce: %w", err)
	}
	return n, nil
}
