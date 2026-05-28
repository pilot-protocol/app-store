package payment

import (
	"bytes"
	"strings"
	"testing"
)

// TestSealRegistry_IDs covers the IDs accessor (was 0% coverage).
func TestSealRegistry_IDs(t *testing.T) {
	t.Parallel()
	r := NewSealRegistry()
	ids := r.IDs()
	if len(ids) != 1 || ids[0] != DefaultSealID {
		t.Errorf("IDs() = %v, want [%s]", ids, DefaultSealID)
	}
}

// TestSealRegistry_IDsAfterRegister covers IDs returning multiple entries.
func TestSealRegistry_IDsAfterRegister(t *testing.T) {
	t.Parallel()
	r := NewSealRegistry()
	_ = r.Register(fakeSeal{id: "fake/v1"})
	ids := r.IDs()
	if len(ids) != 2 {
		t.Errorf("IDs() len = %d, want 2", len(ids))
	}
}

// TestSealRegistry_RegisterNil covers the nil-seal branch.
func TestSealRegistry_RegisterNil(t *testing.T) {
	t.Parallel()
	r := NewSealRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("Register(nil) should error")
	}
}

// TestSealRegistry_RegisterEmptyID covers the empty-ID branch.
func TestSealRegistry_RegisterEmptyID(t *testing.T) {
	t.Parallel()
	r := NewSealRegistry()
	if err := r.Register(fakeSeal{id: ""}); err == nil {
		t.Error("Register(empty ID) should error")
	}
}

// TestSealRegistry_RegisterReplace covers the replacement path (later
// register wins).
func TestSealRegistry_RegisterReplace(t *testing.T) {
	t.Parallel()
	r := NewSealRegistry()
	_ = r.Register(fakeSeal{id: "id1"})
	_ = r.Register(fakeSeal{id: "id1"})
	if got := r.Get("id1"); got == nil {
		t.Error("Get after replace = nil")
	}
}

// TestEncrypt_WrongNonceSize covers the explicit nonce-size check
// branch in Encrypt.
func TestEncrypt_WrongNonceSize(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	key, _ := RandomKey(s)
	badNonce := make([]byte, s.NonceSize()-1)
	_, err := s.Encrypt([]byte("x"), key, badNonce, nil)
	if err == nil || !strings.Contains(err.Error(), "nonce size") {
		t.Errorf("err = %v, want nonce-size error", err)
	}
}

// TestDecrypt_WrongNonceSize covers the explicit nonce-size check in
// Decrypt.
func TestDecrypt_WrongNonceSize(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	key, _ := RandomKey(s)
	badNonce := make([]byte, s.NonceSize()-1)
	_, err := s.Decrypt([]byte("x"), key, badNonce, nil)
	if err == nil || !strings.Contains(err.Error(), "nonce size") {
		t.Errorf("err = %v, want nonce-size error", err)
	}
}

// TestEncrypt_WrongKeySize covers the "new aead: bad key" error path.
func TestEncrypt_WrongKeySize(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	_, err := s.Encrypt([]byte("x"), []byte("too-short-key"), make([]byte, s.NonceSize()), nil)
	if err == nil {
		t.Error("Encrypt with bad key should error")
	}
}

// TestDecrypt_WrongKeySize covers the "new aead: bad key" branch in
// Decrypt.
func TestDecrypt_WrongKeySize(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	_, err := s.Decrypt([]byte("x"), []byte("too-short-key"), make([]byte, s.NonceSize()), nil)
	if err == nil {
		t.Error("Decrypt with bad key should error")
	}
}

// TestRandomKey_SizesMatch confirms keys come back at the seal's
// declared size.
func TestRandomKey_SizesMatch(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	k1, _ := RandomKey(s)
	k2, _ := RandomKey(s)
	if len(k1) != s.KeySize() {
		t.Errorf("key size %d, want %d", len(k1), s.KeySize())
	}
	if bytes.Equal(k1, k2) {
		t.Error("two RandomKey calls returned identical keys")
	}
}

// TestRandomNonce_SizesMatch confirms nonces come back at the seal's
// declared size.
func TestRandomNonce_SizesMatch(t *testing.T) {
	t.Parallel()
	s := DefaultSeal()
	n1, _ := RandomNonce(s)
	n2, _ := RandomNonce(s)
	if len(n1) != s.NonceSize() {
		t.Errorf("nonce size %d, want %d", len(n1), s.NonceSize())
	}
	if bytes.Equal(n1, n2) {
		t.Error("two RandomNonce calls returned identical nonces")
	}
}

// fakeSeal is a stand-in for the seal interface so registry tests can
// exercise Register/Get/IDs without going through chacha20.
type fakeSeal struct{ id string }

func (f fakeSeal) ID() string                            { return f.id }
func (f fakeSeal) KeySize() int                          { return 32 }
func (f fakeSeal) NonceSize() int                        { return 12 }
func (f fakeSeal) Encrypt(p, k, n, a []byte) ([]byte, error) { return p, nil }
func (f fakeSeal) Decrypt(c, k, n, a []byte) ([]byte, error) { return c, nil }
