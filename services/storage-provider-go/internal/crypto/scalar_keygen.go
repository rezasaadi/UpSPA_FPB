// Package crypto provides cryptographic helpers for the Storage Provider service.
//
// Week 2 addition: k_i generation helper derived from RFC 9497 §2.1.
// See INTERN_NOTES/efe-week2.md for the paper-grounded rationale.

package crypto

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

// GenerateScalarKi generates a fresh, uniformly random TOPRF scalar k_i.
//
// This is the correct way to generate k_i per RFC 9497 §2.1 (OPRF):
//
//	"The key generation procedure samples a random scalar in the
//	 multiplicative group of order p using rejection sampling or
//	 a wide-output hash."
//
// We use the wide-output approach: read 64 uniform random bytes and reduce
// modulo the group order l via (*Scalar).SetUniformBytes.  This guarantees:
//   - The result is always in [0, l) — accepted by SetCanonicalBytes on the way in.
//   - The result is statistically indistinguishable from uniform in [0, l).
//
// Why NOT 32 raw random bytes:
//   - The Ristretto255 group order l ≈ 2^252, so roughly half of all 32-byte
//     (256-bit) random values are >= l and would be rejected by SetCanonicalBytes
//     with an error.  Callers would need retry logic and the distribution would
//     be biased toward smaller values.
//   - SetBytesWithClamping (the Ed25519 approach) silently mangles bits and
//     produces the wrong scalar for OPRF purposes (see Bug 1, efe-week2.md).
//
// Returns 32 raw bytes (canonical Ristretto255 scalar encoding).
// The caller is responsible for storing this value; see Sina's DB schema
// (k_i_b64 TEXT) — store the base64url-no-pad encoding via CanonicalB64.
//
// NOTE: do NOT log the return value.
func GenerateScalarKi() ([]byte, error) {
	// 64 uniform bytes → wide reduction mod l (no bias, no rejection needed).
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("GenerateScalarKi: entropy read failed: %w", err)
	}

	s, err := new(edwards25519.Scalar).SetUniformBytes(b)
	if err != nil {
		// SetUniformBytes only fails if len(b) != 64, which cannot happen here.
		return nil, fmt.Errorf("GenerateScalarKi: scalar reduction failed: %w", err)
	}
	return s.Bytes(), nil
}
