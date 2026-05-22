// Package payment is the platform's payment-capability protocol surface.
//
// Three independent extension slots:
//
//   - Method  — produces and verifies proofs-of-payment (e.g. wallet
//     signs a SignedAuth; an on-chain method submits a transaction and
//     returns its hash; Stripe charges a card and returns its session
//     id). Apps implementing Method are how a payer satisfies a
//     Contract.
//
//   - Escrow  — holds the symmetric key behind a sealed message and
//     releases it on a verified Receipt. Sender-self (the wallet) is
//     one impl; a third-party notary is another.
//
//   - Seal    — encrypts the body of a sealed message. Default is
//     chacha20-poly1305 (see pkg/payment/seal package). Other algos
//     can be plugged in by registering a new ID.
//
// The wire types — Contract, Receipt, EscrowRef, SealedEnvelope — are
// transport-agnostic JSON. They flow through hook chains (pkg/extend),
// over pilot's overlay, or through HTTP 402 shims, all the same shape.
package payment

import "time"

// Contract is the abstract statement of what payment is required to
// unseal a message (or satisfy any other gated action).
//
// AcceptedMethods and AcceptedEscrows scope what implementations may
// participate. If empty, defaults are configured by the daemon's
// installed-app policy. Recipients pick any of their installed methods
// whose ID is in AcceptedMethods.
type Contract struct {
	ID              string    `json:"id"`
	Amount          uint64    `json:"amount"`
	Asset           string    `json:"asset"`
	RecipientAddr   string    `json:"recipient_addr"`
	ExpiresAt       time.Time `json:"expires_at"`
	Nonce           string    `json:"nonce"`
	AcceptedMethods []string  `json:"accepted_methods,omitempty"`
	AcceptedEscrows []string  `json:"accepted_escrows,omitempty"`
	Memo            string    `json:"memo,omitempty"`
}

// Receipt is the method-tagged proof a Contract was satisfied. Payload
// is opaque to the platform — only the Method whose ID matches MethodID
// knows how to interpret it. For io.pilot.wallet/v1 the payload is the
// JSON-encoded SignedAuth.
type Receipt struct {
	ContractID string `json:"contract_id"`
	MethodID   string `json:"method_id"`
	Payload    []byte `json:"payload"`
}

// EscrowRef tells a recipient how to redeem K for a contract.
// Endpoint is a pilot address (or, eventually, a URL) at which the
// escrow's Redeem RPC is callable. Token is a handle the escrow uses
// to look up K — opaque to everyone else.
type EscrowRef struct {
	EscrowID   string `json:"escrow_id"`
	Endpoint   string `json:"endpoint"`
	Token      string `json:"token"`
	ContractID string `json:"contract_id"`
}

// SealedEnvelope is what travels on the wire when an app paywalls a
// message body. The recipient holds the ciphertext locally; when they
// decide to pay, they fetch K from the EscrowRef using a Receipt, and
// decrypt with the named Seal.
type SealedEnvelope struct {
	Contract   Contract  `json:"contract"`
	EscrowRef  EscrowRef `json:"escrow_ref"`
	SealID     string    `json:"seal_id"`
	Ciphertext []byte    `json:"ciphertext"`
	Nonce      []byte    `json:"nonce"`
	SenderAddr string    `json:"sender_addr"`
}
