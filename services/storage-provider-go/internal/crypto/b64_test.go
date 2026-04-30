// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go"
)

func TestCanonicalB64_RoundTrip(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)

	encoded := base64.RawURLEncoding.EncodeToString(raw)
	canon, got, err := crypto.CanonicalB64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if canon != encoded {
		t.Errorf("canon mismatch: want %q got %q", encoded, canon)
	}
	if string(got) != string(raw) {
		t.Error("decoded bytes differ from original")
	}
}

func TestCanonicalB64_AcceptsPadded(t *testing.T) {
	raw := make([]byte, 10)
	rand.Read(raw)

	padded := base64.URLEncoding.EncodeToString(raw)
	canon, got, err := crypto.CanonicalB64(padded)
	if err != nil {
		t.Fatalf("unexpected error on padded input: %v", err)
	}
	if string(got) != string(raw) {
		t.Error("decoded bytes differ from original")
	}
	// canonical output must never contain '='
	for _, c := range canon {
		if c == '=' {
			t.Error("canonical output contains padding")
		}
	}
}

func TestCanonicalB64_RejectsInvalid(t *testing.T) {
	_, _, err := crypto.CanonicalB64("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64, got %v", err)
	}
}

func TestDecodeFixedB64_CorrectLength(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	decoded, canon, err := crypto.DecodeFixedB64(encoded, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("wrong length: %d", len(decoded))
	}
	if canon != encoded {
		t.Errorf("non-canonical output")
	}
}

func TestDecodeFixedB64_WrongLength(t *testing.T) {
	raw := make([]byte, 16)
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	_, _, err := crypto.DecodeFixedB64(encoded, 32)
	if err == nil {
		t.Fatal("expected ErrWrongLength")
	}
	if !errors.Is(err, crypto.ErrWrongLength) {
		t.Errorf("want ErrWrongLength, got %v", err)
	}
}

func TestDecodeFixedB64_InvalidBase64(t *testing.T) {
	_, _, err := crypto.DecodeFixedB64("@@@@", 32)
	if !errors.Is(err, crypto.ErrInvalidBase64) {
		t.Errorf("want ErrInvalidBase64, got %v", err)
	}
}

func TestLenConstants(t *testing.T) {
	cases := map[string]int{
		"LenEd25519PublicKey": crypto.LenEd25519PublicKey,
		"LenEd25519Signature": crypto.LenEd25519Signature,
		"LenCtBlobNonce":      crypto.LenCtBlobNonce,
		"LenCtBlobTag":        crypto.LenCtBlobTag,
		"LenRistretto":        crypto.LenRistretto,
		"LenScalarKi":         crypto.LenScalarKi,
	}
	expected := map[string]int{
		"LenEd25519PublicKey": 32,
		"LenEd25519Signature": 64,
		"LenCtBlobNonce":      24,
		"LenCtBlobTag":        16,
		"LenRistretto":        32,
		"LenScalarKi":         32,
	}
	for name, got := range cases {
		if want := expected[name]; got != want {
			t.Errorf("%s: want %d got %d", name, want, got)
		}
	}
}
