// April: Expanded negative test suite.
//
// Covers every rejection category the protocol requires (HTTP 400):
//   - Malformed base64 (whitespace, null bytes, wrong alphabet)
//   - Wrong byte lengths for every fixed-size wire field
//   - Invalid Ristretto255 point encodings (per RFC 9496 §4.3.1)
//   - Invalid (non-canonical) scalar encodings
//   - VerifyEd25519 panic guards for wrong-length inputs
//
// Update (Week 4 Patch B): import path corrected from the placeholder
// "github.com/rezasaadi/UpSPA_FPB/..." to "upspa/internal/crypto" matching
// the actual go.mod module declaration. Invalid-point vectors switched to
// Ristretto255-specific (RFC 9496) ones now that ristretto.go uses
// gtank/ristretto255 rather than the previous Edwards25519 encoding.

package crypto_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"upspa/internal/crypto"
)

// ---------------------------------------------------------------------------
// helper
// ---------------------------------------------------------------------------

func b64Zeros(n int) string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, n))
}

// ---------------------------------------------------------------------------
// Malformed base64
// ---------------------------------------------------------------------------

func TestCanonicalB64_Negative_StandardAlphabetPlusSlash(t *testing.T) {
	// '+' and '/' are not in the base64url alphabet.
	_, _, err := crypto.CanonicalB64("+/8=")
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64 for '+/' chars, got %v", err)
	}
}

func TestCanonicalB64_Negative_Punctuation(t *testing.T) {
	cases := []string{
		"!!!not-base64!!!",
		"@#$%^&*()",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
	}
	for _, c := range cases {
		if _, _, err := crypto.CanonicalB64(c); !errors.Is(err, crypto.ErrInvalidBase64) {
			t.Errorf("input %q: want ErrInvalidBase64, got %v", c, err)
		}
	}
}

func TestCanonicalB64_Negative_EmbeddedWhitespace(t *testing.T) {
	// Note: Go 1.22+ base64.RawURLEncoding silently skips \n and \r\n,
	// so those are NOT testable as rejections — they canonicalize fine.
	cases := []string{
		"dGVz dA",  // space — rejected
		"dGVz\tdA", // tab  — rejected
		" dGVzdA",  // leading space — rejected
		"dGVzdA ",  // trailing space — rejected
	}
	for _, c := range cases {
		if _, _, err := crypto.CanonicalB64(c); !errors.Is(err, crypto.ErrInvalidBase64) {
			t.Errorf("input %q: want ErrInvalidBase64, got %v", c, err)
		}
	}
}

func TestCanonicalB64_Negative_NullBytes(t *testing.T) {
	_, _, err := crypto.CanonicalB64("\x00\x00\x00\x00")
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64 for null bytes, got %v", err)
	}
}

func TestCanonicalB64_Negative_HighByteChars(t *testing.T) {
	_, _, err := crypto.CanonicalB64("\xff\xfe\xfd")
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64 for non-ASCII bytes, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Wrong byte lengths — one helper, called for every field type
// ---------------------------------------------------------------------------

func assertWrongLength(t *testing.T, fieldName string, wantLen int, badLens []int) {
	t.Helper()
	for _, l := range badLens {
		_, _, err := crypto.DecodeFixedB64(b64Zeros(l), wantLen)
		if !errors.Is(err, crypto.ErrWrongLength) {
			t.Errorf("%s: input %d bytes, want %d: expected ErrWrongLength, got %v",
				fieldName, l, wantLen, err)
		}
	}
}

func TestDecodeFixedB64_Negative_Ed25519PublicKey(t *testing.T) {
	assertWrongLength(t, "Ed25519PublicKey", crypto.LenEd25519PublicKey,
		[]int{0, 1, 16, 31, 33, 48, 64})
}

func TestDecodeFixedB64_Negative_Ed25519Signature(t *testing.T) {
	assertWrongLength(t, "Ed25519Signature", crypto.LenEd25519Signature,
		[]int{0, 1, 32, 63, 65, 128})
}

func TestDecodeFixedB64_Negative_CtBlobNonce(t *testing.T) {
	assertWrongLength(t, "CtBlobNonce", crypto.LenCtBlobNonce,
		[]int{0, 1, 16, 23, 25, 32})
}

func TestDecodeFixedB64_Negative_CtBlobTag(t *testing.T) {
	assertWrongLength(t, "CtBlobTag", crypto.LenCtBlobTag,
		[]int{0, 1, 8, 15, 17, 32})
}

func TestDecodeFixedB64_Negative_Ristretto(t *testing.T) {
	assertWrongLength(t, "Ristretto", crypto.LenRistretto,
		[]int{0, 1, 16, 31, 33, 64})
}

func TestDecodeFixedB64_Negative_ScalarKi(t *testing.T) {
	assertWrongLength(t, "ScalarKi", crypto.LenScalarKi,
		[]int{0, 1, 16, 31, 33, 64})
}

func TestDecodeFixedB64_Negative_InvalidBase64WinsOverWrongLength(t *testing.T) {
	_, _, err := crypto.DecodeFixedB64("!!!bad!!!", 32)
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64 for completely invalid input, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Invalid Ristretto255 point encodings (RFC 9496 §4.3.1)
// ---------------------------------------------------------------------------

func TestRistrettoScalarMult_Negative_InvalidPoints(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 1 // canonical scalar = 1

	// Per RFC 9496 §4.3.1, the decode procedure rejects:
	//   1. encodings whose top bit (s[31] & 0x80) is set,
	//   2. encodings of non-canonical field elements (s >= p),
	//   3. encodings that do not lie in the Ristretto element set.
	//
	// We pin a few cases from each rejection class.
	cases := []struct {
		name  string
		point []byte
	}{
		{
			// Top bit set in last byte → step 1 rejection.
			name:  "high-bit set (0xFF*32)",
			point: bytes.Repeat([]byte{0xFF}, 32),
		},
		{
			// Top bit set in last byte, otherwise zero → step 1 rejection.
			name:  "last byte 0x80",
			point: func() []byte { p := make([]byte, 32); p[31] = 0x80; return p }(),
		},
		{
			// Non-canonical field element: value > p.
			// p = 2^255 - 19, so encoding (0xED, 0xFF*30, 0x7F) = p, and any
			// value above p is non-canonical. We use (0xEE, 0xFF*30, 0x7F) = p+1.
			name: "non-canonical field element (p+1)",
			point: func() []byte {
				p := make([]byte, 32)
				p[0] = 0xEE
				for i := 1; i < 31; i++ {
					p[i] = 0xFF
				}
				p[31] = 0x7F
				return p
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.RistrettoScalarMult(k, tc.point)
			if err == nil {
				t.Fatal("expected error for invalid Ristretto point")
			}
			if !errors.Is(err, crypto.ErrInvalidPoint) {
				t.Errorf("want ErrInvalidPoint, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Invalid (non-canonical) scalar encodings
// ---------------------------------------------------------------------------

func TestRistrettoScalarMult_Negative_InvalidScalars(t *testing.T) {
	point := validRistrettoPoint()

	cases := []struct {
		name   string
		scalar []byte
	}{
		{"all 0xFF (>> l)", bytes.Repeat([]byte{0xFF}, 32)},
		{"all 0x7F (> l)", bytes.Repeat([]byte{0x7F}, 32)},
		{
			// l = 2^252 + 27742317777372353535851937790883648493 in little-endian
			"scalar equals l",
			[]byte{
				0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
				0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			},
		},
		{
			"scalar equals l+1",
			[]byte{
				0xee, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
				0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.RistrettoScalarMult(tc.scalar, point)
			if err == nil {
				t.Fatal("expected error for non-canonical scalar")
			}
			if !errors.Is(err, crypto.ErrInvalidScalar) {
				t.Errorf("want ErrInvalidScalar, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wrong lengths for RistrettoScalarMult inputs
// ---------------------------------------------------------------------------

func TestRistrettoScalarMult_Negative_ScalarWrongLengths(t *testing.T) {
	point := validRistrettoPoint()
	for _, badLen := range []int{0, 1, 16, 31, 33, 64} {
		_, err := crypto.RistrettoScalarMult(make([]byte, badLen), point)
		if !errors.Is(err, crypto.ErrWrongLength) {
			t.Errorf("scalar len=%d: want ErrWrongLength, got %v", badLen, err)
		}
	}
}

func TestRistrettoScalarMult_Negative_PointWrongLengths(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 1
	for _, badLen := range []int{0, 1, 16, 31, 33, 64} {
		_, err := crypto.RistrettoScalarMult(k, make([]byte, badLen))
		if !errors.Is(err, crypto.ErrWrongLength) {
			t.Errorf("point len=%d: want ErrWrongLength, got %v", badLen, err)
		}
	}
}

// ---------------------------------------------------------------------------
// VerifyEd25519 panic guards
// ---------------------------------------------------------------------------

func TestVerifyEd25519_Negative_ShortKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for sigPk len=31")
		}
	}()
	_ = crypto.VerifyEd25519(make([]byte, 31), []byte("msg"), make([]byte, 64))
}

func TestVerifyEd25519_Negative_LongKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for sigPk len=33")
		}
	}()
	_ = crypto.VerifyEd25519(make([]byte, 33), []byte("msg"), make([]byte, 64))
}

func TestVerifyEd25519_Negative_ShortSigPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for sig len=63")
		}
	}()
	_ = crypto.VerifyEd25519(make([]byte, 32), []byte("msg"), make([]byte, 63))
}

func TestVerifyEd25519_Negative_LongSigPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for sig len=65")
		}
	}()
	_ = crypto.VerifyEd25519(make([]byte, 32), []byte("msg"), make([]byte, 65))
}
