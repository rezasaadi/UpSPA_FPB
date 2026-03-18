// Package crypto provides cryptographic helpers for the Storage Provider service.
//
// Week 3 stretch: Extracted all field-length constants into this file so there
// is a single canonical source of truth. All other files in this package
// (and callers in internal/api) import these constants by name rather than
// embedding magic numbers.
//
// Rule: every fixed-length field in the SP wire protocol must have a Len*
// constant here. Adding a new field to the protocol means adding it here first.

package crypto

// ---------------------------------------------------------------------------
// Wire-format byte-length constants (Shared Contract §2 in Baseline.md)
//
// These values are the ground truth for the SP protocol. Changing any of
// them is a breaking wire-format change and requires a coordinated update
// across all layers (API, DB, client).
// ---------------------------------------------------------------------------

const (
	// LenEd25519PublicKey is the byte length of an Ed25519 public key (RFC 8032).
	LenEd25519PublicKey = 32

	// LenEd25519Signature is the byte length of an Ed25519 signature (RFC 8032).
	LenEd25519Signature = 64

	// LenCtBlobNonce is the byte length of the AEAD nonce stored in a ciphertext blob.
	// XSalsa20-Poly1305 / NaCl secretbox nonces are 24 bytes.
	LenCtBlobNonce = 24

	// LenCtBlobTag is the byte length of the AEAD authentication tag in a ciphertext blob.
	// Poly1305 tags are 16 bytes.
	LenCtBlobTag = 16

	// LenRistretto is the byte length of a Ristretto255-encoded group element.
	// Reference: https://ristretto.group/
	LenRistretto = 32

	// LenScalarKi is the byte length of a TOPRF scalar share k_i.
	// Must equal the Ristretto255 scalar size (32 bytes, fully-reduced in [0,l)).
	LenScalarKi = 32
)

// ---------------------------------------------------------------------------
// Derived message-layout constants (from docs/protocol-phases.md)
//
// These constants describe fixed-size sub-regions of the password-update
// signature message. They are NOT wire fields themselves — they are offsets
// and sizes that depend on the constants above, and are provided here to
// make BuildPwdUpdateSigMsg and its tests readable without magic numbers.
// ---------------------------------------------------------------------------

const (
	// LenTimestamp is the byte length of the password-update timestamp
	// (little-endian uint64).
	LenTimestamp = 8

	// LenSpID is the byte length of the SP identifier in the password-update
	// signature message (little-endian uint32).
	LenSpID = 4

	// PwdUpdateSigMsgFixedLen is the byte length of BuildPwdUpdateSigMsg output
	// when cidCt is empty. The real length is PwdUpdateSigMsgFixedLen + len(cidCt).
	//
	//   cidNonce (24) + cidCt (0) + cidTag (16) + kINew (32) + ts (8) + spID (4) = 84
	PwdUpdateSigMsgFixedLen = LenCtBlobNonce + LenCtBlobTag + LenScalarKi + LenTimestamp + LenSpID
)
