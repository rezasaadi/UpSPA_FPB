// April: Switched the underlying library from filippo.io/edwards25519 to
// github.com/gtank/ristretto255.

// Reason: the previous code used edwards25519.Point.SetBytes / .Bytes(), which
// is the *Edwards25519* compressed encoding. The Rust client encodes blinded
// points via curve25519_dalek::ristretto::CompressedRistretto — a different
// 32-byte encoding. The two are not interchangeable: a 32-byte string that is
// a valid Ristretto255 encoding either fails to decode as Edwards25519 or
// decodes to a different group element. Unit tests passed because they used
// edwards25519.NewGeneratorPoint().Bytes() throughout, never a real
// Ristretto255 wire byte string. At integration time, every TOPRF eval would
// have returned an incorrect or rejected point.

// gtank/ristretto255 implements RFC 9496 (the Ristretto255 specification) and
// is wire-compatible with curve25519-dalek's CompressedRistretto.

package crypto

import (
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

// ErrInvalidPoint is returned when a Ristretto255-encoded point is invalid.
var ErrInvalidPoint = errors.New("invalid_ristretto_point")

// ErrInvalidScalar is returned when bytes do not represent a canonical
// Ristretto255 scalar (i.e. value >= group order l).
var ErrInvalidScalar = errors.New("invalid_ristretto_scalar")

// RistrettoScalarMult computes y = k * blinded where:
//   - k       is a LenScalarKi (32-byte) canonical scalar (TOPRF share k_i)
//   - blinded is a LenRistretto (32-byte) Ristretto255-encoded point
//
// Returns y as a 32-byte Ristretto255-encoded point.
//
// Errors:
//   - ErrWrongLength    if k or blinded have wrong byte lengths
//   - ErrInvalidScalar  if k is not a canonical scalar (value >= group order l)
//   - ErrInvalidPoint   if blinded does not decode as a valid Ristretto255 point
//
// Reference: RFC 9496 (Ristretto255 / Decaf448).
//
// NOTE: do NOT log k, blinded, or y — these are secret / sensitive curve values.
func RistrettoScalarMult(k []byte, blinded []byte) (y []byte, err error) {
	if len(k) != LenScalarKi {
		return nil, fmt.Errorf("%w: scalar k must be %d bytes, got %d",
			ErrWrongLength, LenScalarKi, len(k))
	}
	if len(blinded) != LenRistretto {
		return nil, fmt.Errorf("%w: blinded point must be %d bytes, got %d",
			ErrWrongLength, LenRistretto, len(blinded))
	}

	// Decode the scalar canonically. Decode rejects values >= l, returning an
	// error rather than silently reducing — which is the correct behaviour for
	// wire inputs (caller must map this to HTTP 400).
	//
	// Note: we deliberately do NOT use any clamping helper. Clamping is for
	// Ed25519/X25519 private keys — it forces specific bit patterns and would
	// silently compute  clamp(k_i) * blinded  instead of  k_i * blinded,
	// breaking the TOPRF protocol with no error signal.
	scalar := ristretto255.NewScalar()
	if err := scalar.Decode(k); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidScalar, err)
	}

	// Decode the Ristretto255-encoded point. Per RFC 9496, this rejects any
	// non-canonical encoding (negative field elements, wrong sign bit,
	// off-curve, low-order, etc.).
	point := ristretto255.NewElement()
	if err := point.Decode(blinded); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPoint, err)
	}

	// y = k * blinded
	result := ristretto255.NewElement().ScalarMult(scalar, point)

	// Encode appends 32 bytes of canonical Ristretto255 encoding.
	return result.Encode(make([]byte, 0, LenRistretto)), nil
}
