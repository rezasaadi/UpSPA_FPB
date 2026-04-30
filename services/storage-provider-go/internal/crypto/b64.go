// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

// Package crypto provides cryptographic helpers for the Storage Provider service.
//
// Ownership: Efe (intern/efe/...)
//
// Security rules:
//   - NEVER log uid / suid / cid / cj / k_i / signatures / curve points.
//   - All base64 inputs are re-encoded to canonical form before use/storage.
//   - Wrong byte lengths → caller must return 400.

package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrInvalidBase64 is returned when a string is not valid base64url-no-pad.
var ErrInvalidBase64 = errors.New("invalid_base64")

// ErrWrongLength is returned when decoded bytes have an unexpected length.
var ErrWrongLength = errors.New("wrong_byte_length")

// enc is the canonical encoding: base64url, no padding (RFC 4648 §5).
// Reference: https://pkg.go.dev/encoding/base64
var enc = base64.RawURLEncoding

// Fixed byte-length constants (Shared Contract §2).
// CanonicalB64 decodes a base64url string (with or without padding) and
// re-encodes it in canonical base64url-no-pad form.
//
// Returns:
//   - canon: canonical base64url-no-pad string (safe to store / compare)
//   - raw:   decoded bytes
//   - err:   ErrInvalidBase64 on any decode failure
//
// NOTE: do NOT include raw in log output for secret fields.
func CanonicalB64(s string) (canon string, raw []byte, err error) {
	raw, err = enc.DecodeString(s)
	if err != nil {
		// Fallback: try standard base64url with padding.
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %w", ErrInvalidBase64, err)
		}
	}
	canon = enc.EncodeToString(raw)
	return canon, raw, nil
}

// DecodeFixedB64 decodes a base64url-no-pad string and enforces an exact byte
// length n. Returns canonical form alongside raw bytes.
//
// Returns ErrInvalidBase64 on bad encoding, ErrWrongLength on length mismatch.
//
// NOTE: do NOT include raw or canon in log output for secret fields.
func DecodeFixedB64(s string, n int) (raw []byte, canon string, err error) {
	canon, raw, err = CanonicalB64(s)
	if err != nil {
		return nil, "", err
	}
	if len(raw) != n {
		return nil, "", fmt.Errorf("%w: want %d bytes, got %d", ErrWrongLength, n, len(raw))
	}
	return raw, canon, nil
}
