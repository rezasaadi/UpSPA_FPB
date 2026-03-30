// Week 2: Fixed invalid-point test (all-zeros is the Ristretto255 identity,
// not an invalid encoding). Added ErrInvalidScalar test. See INTERN_NOTES/efe-week2.md.

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go/internal/crypto"
)

// validRistrettoPoint returns a known-valid Ristretto255 point (the base point).
func validRistrettoPoint() []byte {
	return edwards25519.NewGeneratorPoint().Bytes()
}

func TestRistrettoScalarMult_ValidInputs(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	// Reduce k so it is a canonical scalar (value < group order l).
	k[31] &= 0x0f

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
	k[0] = 1

	// NOTE: all-zeros (make([]byte,32)) is the Ristretto255 IDENTITY point —
	// a valid encoding. Use 0xFF*32 instead, which is not a valid encoding.
	badPoint := bytes.Repeat([]byte{0x02}, 32)
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
	k[0] = 1
	identity := make([]byte, 32)
	_, err := crypto.RistrettoScalarMult(k, identity)
	if errors.Is(err, crypto.ErrInvalidPoint) {
		t.Error("all-zeros is the Ristretto255 identity point and must be accepted")
	}
}
