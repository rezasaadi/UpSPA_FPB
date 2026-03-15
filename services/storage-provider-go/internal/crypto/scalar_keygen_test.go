// Week 2: Tests for GenerateScalarKi — correct k_i generation per RFC 9497.

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/your-org/sp/internal/crypto"
)

func TestGenerateScalarKi_Length(t *testing.T) {
	ki, err := crypto.GenerateScalarKi()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ki) != crypto.LenScalarKi {
		t.Errorf("want %d bytes, got %d", crypto.LenScalarKi, len(ki))
	}
}

func TestGenerateScalarKi_IsCanonical(t *testing.T) {
	// Every value produced by GenerateScalarKi must be accepted by
	// RistrettoScalarMult (i.e. pass SetCanonicalBytes).
	// Run many iterations to catch any bias or edge cases.
	basePoint := validRistrettoPoint()
	for i := 0; i < 100; i++ {
		ki, err := crypto.GenerateScalarKi()
		if err != nil {
			t.Fatalf("iter %d: GenerateScalarKi error: %v", i, err)
		}
		_, err = crypto.RistrettoScalarMult(ki, basePoint)
		if err != nil {
			t.Fatalf("iter %d: generated k_i rejected by RistrettoScalarMult: %v", i, err)
		}
	}
}

func TestGenerateScalarKi_Unique(t *testing.T) {
	// Two independently generated scalars should (with overwhelming probability)
	// be distinct.
	ki1, err1 := crypto.GenerateScalarKi()
	ki2, err2 := crypto.GenerateScalarKi()
	if err1 != nil || err2 != nil {
		t.Fatalf("generation error: %v / %v", err1, err2)
	}
	if bytes.Equal(ki1, ki2) {
		t.Error("two independently generated k_i values are identical (RNG failure?)")
	}
}

func TestGenerateScalarKi_NotAllZeros(t *testing.T) {
	// The zero scalar would make TOPRF trivially insecure (0 * P = identity for all P).
	// Verify the generator never produces it.
	for i := 0; i < 20; i++ {
		ki, _ := crypto.GenerateScalarKi()
		if bytes.Equal(ki, make([]byte, 32)) {
			t.Fatal("generated zero scalar — catastrophic RNG failure")
		}
	}
}
