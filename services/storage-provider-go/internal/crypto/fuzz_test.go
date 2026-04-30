// Week 4: Fuzz tests for CanonicalB64 and DecodeFixedB64.
//
// Run with:
//   go test -fuzz=FuzzCanonicalB64    ./internal/crypto/...
//   go test -fuzz=FuzzDecodeFixedB64  ./internal/crypto/...
//
// Invariants enforced:
//  1. If CanonicalB64 succeeds, the canonical string must round-trip cleanly.
//  2. Canonicalization is idempotent: canon(canon(x)) == canon(x).
//  3. If DecodeFixedB64 succeeds, the returned slice has exactly n bytes.

package crypto_test

import (
	"encoding/base64"
	"testing"

	"github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go"
)

// FuzzCanonicalB64 verifies round-trip correctness and idempotence.
func FuzzCanonicalB64(f *testing.F) {
	seeds := []string{
		"",
		"YQ",
		"YWI",
		"YWJj",
		"AAAA",
		"AAECBA",
		"YQ==",
		"YWI=",
		"!!!not-base64!!!",
		"dGVzdA",
		"dGVzdA==",
		" dGVzdA",
		"dGVz dA",
		"dGVz\ndA",
		"+/8=",
		"\x00\x00",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		canon, raw, err := crypto.CanonicalB64(input)
		if err != nil {
			return
		}

		// Invariant 1: canonical string must decode back to the same bytes.
		raw2, err2 := base64.RawURLEncoding.DecodeString(canon)
		if err2 != nil {
			t.Errorf("canonical string %q failed to re-decode: %v", canon, err2)
		}
		if string(raw) != string(raw2) {
			t.Errorf("round-trip byte mismatch for input %q", input)
		}

		// Invariant 2: canonicalization must be idempotent.
		canon2, _, err3 := crypto.CanonicalB64(canon)
		if err3 != nil {
			t.Errorf("re-canonicalizing already-canonical string %q returned error: %v", canon, err3)
		}
		if canon != canon2 {
			t.Errorf("not idempotent: input %q → %q → %q", input, canon, canon2)
		}
	})
}

// FuzzDecodeFixedB64 verifies that on success the returned slice has exactly n bytes.
func FuzzDecodeFixedB64(f *testing.F) {
	// Seed with (input, expected_length) pairs covering all protocol field sizes.
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 32)
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 64)), 64)
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 24)), 24)
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 16)), 16)
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 31)), 32) // wrong len
	f.Add("!!!bad!!!", 32)
	f.Add("", 32)
	f.Add("", 0)

	f.Fuzz(func(t *testing.T, input string, n int) {
		if n < 0 || n > 4096 {
			return
		}
		raw, _, err := crypto.DecodeFixedB64(input, n)
		if err != nil {
			return
		}
		// Invariant 3: on success, returned slice must have exactly n bytes.
		if len(raw) != n {
			t.Errorf("DecodeFixedB64(%q, %d) returned %d bytes, want %d",
				input, n, len(raw), n)
		}
	})
}
