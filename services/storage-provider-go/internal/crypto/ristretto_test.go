// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

// Week 2: Fixed invalid-point test (all-zeros is the Ristretto255 identity,
// not an invalid encoding). Added ErrInvalidScalar test. See efe-week2.md.

/*Bugs are added.
Bug 2 — ristretto_test.go: make([]byte, 32) (all-zeros) is the Ristretto255 identity point encoding 
— it's valid, so the test expecting ErrInvalidPoint would pass by accident on some builds and fail on others depending on version. 
A genuinely invalid encoding (e.g. 0xFF * 32) is needed.
*/
package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/your-org/sp/internal/crypto"
)

// validRistrettoPoint returns a known-valid Ristretto255 point (the base point).
func validRistrettoPoint() []byte {
	// Use the Edwards25519 base point, which is also a valid Ristretto255 point.
	return edwards25519.NewGeneratorPoint().Bytes()
}

func TestRistrettoScalarMult_ValidInputs(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	// Reduce k so it is a canonical scalar (value < group order l).
	// In production, k_i is always generated as a canonical scalar.
	k[31] &= 0x0f // clear high bits to ensure value < l

	point := validRistrettoPoint()
	y, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(y) != 32 {
		t.Errorf("expected 32-byte output, got %d", len(y))
	}
}

func TestRistrettoScalarMult_Deterministic(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	k[31] &= 0x0f
	point := validRistrettoPoint()

	y1, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatal(err)
	}
	y2, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatal(err)
	}
	if string(y1) != string(y2) {
		t.Error("RistrettoScalarMult is not deterministic")
	}
}

func TestRistrettoScalarMult_DifferentKeys_DifferentOutputs(t *testing.T) {
	// Use two small distinct canonical scalars (values 1 and 2).
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k1[0] = 1
	k2[0] = 2
	point := validRistrettoPoint()

	y1, err := crypto.RistrettoScalarMult(k1, point)
	if err != nil {
		t.Fatal(err)
	}
	y2, err := crypto.RistrettoScalarMult(k2, point)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(y1, y2) {
		t.Error("different scalars should produce different outputs")
	}
}

func TestRistrettoScalarMult_InvalidPoint(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 1 // canonical scalar = 1

	// NOTE: all-zeros (make([]byte,32)) is the Ristretto255 IDENTITY point —
	// a valid encoding. Use 0xFF*32 instead, which is not a valid encoding.
	badPoint := bytes.Repeat([]byte{0xFF}, 32)
	_, err := crypto.RistrettoScalarMult(k, badPoint)
	if err == nil {
		t.Fatal("expected error for invalid Ristretto point")
	}
	if !errors.Is(err, crypto.ErrInvalidPoint) {
		t.Errorf("want ErrInvalidPoint, got %v", err)
	}
}

func TestRistrettoScalarMult_InvalidScalar(t *testing.T) {
	// A scalar value >= group order l is not canonical.
	// l = 2^252 + 27742317777372353535851937790883648493
	// Setting all bytes to 0xFF gives a value >> l.
	badScalar := bytes.Repeat([]byte{0xFF}, 32)
	_, err := crypto.RistrettoScalarMult(badScalar, validRistrettoPoint())
	if err == nil {
		t.Fatal("expected error for non-canonical scalar")
	}
	if !errors.Is(err, crypto.ErrInvalidScalar) {
		t.Errorf("want ErrInvalidScalar, got %v", err)
	}
}

func TestRistrettoScalarMult_WrongScalarLength(t *testing.T) {
	_, err := crypto.RistrettoScalarMult(make([]byte, 16), validRistrettoPoint())
	if !errors.Is(err, crypto.ErrWrongLength) {
		t.Errorf("want ErrWrongLength for short scalar, got %v", err)
	}
}

func TestRistrettoScalarMult_WrongPointLength(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 1
	_, err := crypto.RistrettoScalarMult(k, make([]byte, 16))
	if !errors.Is(err, crypto.ErrWrongLength) {
		t.Errorf("want ErrWrongLength for short point, got %v", err)
	}
}

func TestRistrettoScalarMult_IdentityPoint_IsValid(t *testing.T) {
	// Explicit regression: the all-zero encoding IS the Ristretto255 identity
	// and must NOT return ErrInvalidPoint.
	k := make([]byte, 32)
	k[0] = 1 // scalar = 1
	identity := make([]byte, 32)
	_, err := crypto.RistrettoScalarMult(k, identity)
	if errors.Is(err, crypto.ErrInvalidPoint) {
		t.Error("all-zeros is the Ristretto255 identity point and must be accepted")
	}
}
