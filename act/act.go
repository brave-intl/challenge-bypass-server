// Package act wraps Anonymous Credit Tokens (draft-schlesinger-cfrg-act,
// draft-schlesinger-privacypass-act) for challenge-bypass-server.
//
// The crypto lives in the Rust crate under ffi/ and is linked only when the
// binary is built with the "act" build tag. Without the tag every function
// returns ErrUnavailable, so default builds are unaffected.
//
// Protocol messages (requests, responses, proofs, refunds, credentials) are the
// crate's CBOR encodings, passed through as opaque bytes.
package act

import "errors"

// CreditBits is the range-proof bit length (L). Balances and charges must be
// at most MaxCredits. Spend proofs are 32*(14+4L) bytes (~4.5 KB).
const CreditBits = 32

// MaxCredits is the largest balance or charge a credential can carry.
const MaxCredits = uint64(1)<<CreditBits - 1

var (
	// ErrUnavailable - binary was built without the "act" build tag
	ErrUnavailable = errors.New("act: not built with ACT support (build tag \"act\")")
	// ErrInvalidProof - a proof or signature failed verification
	ErrInvalidProof = errors.New("act: invalid proof")
	// ErrMalformed - an input could not be decoded
	ErrMalformed = errors.New("act: malformed input")
	// ErrInvalidAmount - a credit amount is zero where not allowed, too large, or a refund exceeds the charge
	ErrInvalidAmount = errors.New("act: invalid credit amount")
	// ErrInternal - unexpected failure inside the crypto library
	ErrInternal = errors.New("act: internal error")
)

// SpendInfo is what the issuer learns from a verified spend proof.
type SpendInfo struct {
	// Nullifier uniquely identifies the spent credential; record it to stop double spends.
	Nullifier [32]byte
	// Context is the credential context scalar the credential was issued under.
	Context [32]byte
	// Charge is the number of credits the client is spending (the hold).
	Charge uint64
}
