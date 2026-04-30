# Efe — April (post Week 4 March follow-up)

**Branch:** `intern/efe/...`
**Package:** `internal/crypto/**`
**Scope:** correctness + buildability of the `internal/crypto/` package.

This patch is a follow-up to Week 4. It addresses two issues that surfaced
when I sat down to wire `internal/crypto/` into a real test harness rather
than running the unit tests in isolation. Both issues would only have shown
up at integration time, which made them important to catch and fix before
the integration meetings.

---

## Issue 1 — Test files do not build against the actual `go.mod`

`go.mod` declares `module upspa`, so the canonical internal import for this
package is `upspa/internal/crypto` (which is what every production file
under `internal/api/`, `cmd/sp/`, etc. uses).

The seven `*_test.go` files in `internal/crypto/` were importing two
different non-matching paths:

| File | Import path used | Status |
|---|---|---|
| `b64_test.go` | `github.com/your-org/sp/internal/crypto` | template placeholder, never updated |
| `ed25519_test.go` | `github.com/your-org/sp/internal/crypto` | same |
| `pwd_update_sigmsg_test.go` | `github.com/your-org/sp/internal/crypto` | same |
| `scalar_keygen_test.go` | `github.com/your-org/sp/internal/crypto` | same |
| `fuzz_test.go` | `github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go/internal/crypto` | path I assumed go.mod would be updated to in week 4 |
| `negative_test.go` | same as above | same |
| `ristretto_test.go` | same as above | same |

Result: `go test ./internal/crypto/...` fails with
`package github.com/... is not in std (...): cannot find module`
**before any test runs.** All four week-1/2/3 tests, the fuzz suite, and
the week-4 negative suite were unrunnable in this state.

**Fix:** every test file now imports `upspa/internal/crypto`, matching
`go.mod`. Applied via `apply_patch_b.sh` (sed-based, no logic changes).

---

## Issue 2 — Encoding mismatch in `ristretto.go` (Edwards25519 vs Ristretto255)

The previous `ristretto.go` imported `filippo.io/edwards25519` and used:

```go
point, err := new(edwards25519.Point).SetBytes(blinded)
...
return result.Bytes(), nil
```

`edwards25519.Point.SetBytes` decodes the **Edwards25519 compressed
encoding** (32-byte y-coordinate + sign bit). The Rust client encodes
blinded points using `curve25519_dalek::ristretto::CompressedRistretto`,
which is the **Ristretto255 encoding** (RFC 9496) — a different 32-byte
format. The same byte string does not represent the same group element
under the two encodings: Ristretto255 input bytes either fail to decode as
Edwards25519, or decode to a wrong point. Either way, `y_i = k_i * blinded`
returned to the client is incorrect, and the client's TOPRF combination
step rejects it.

The unit tests didn't catch this because they used
`edwards25519.NewGeneratorPoint().Bytes()` end-to-end, never a
Ristretto255-encoded byte string. The protocol-level invariant
*"the Go server can scalar-multiply a `CompressedRistretto` produced by
the Rust client"* was never tested.

**Fix:** rewrote `ristretto.go` against `github.com/gtank/ristretto255`,
which is RFC 9496 and wire-compatible with curve25519-dalek's
`CompressedRistretto`. Public API and error sentinels (`ErrInvalidPoint`,
`ErrInvalidScalar`, `ErrWrongLength`) are unchanged — callers in
`internal/api/` need no edits.

`scalar_keygen.go` is unchanged: it uses `edwards25519.Scalar` for the
wide-reduction key generation, which produces canonical 32-byte scalar
bytes that the new `ristretto255.Scalar.Decode` consumes correctly.
The Ristretto255 scalar field IS the Ed25519 scalar field — both are
integers mod the prime-order subgroup order *l*.

**Test additions:**
- `TestRistrettoScalarMult_OneTimesG_RoundTrip` — pins `1 * G == G` against
  the canonical Ristretto255 generator. This is the test the previous
  encoding silently failed: with Edwards25519 generator bytes, `1 * G`
  re-encodes as the Edwards25519 generator, not the Ristretto255 generator.
- Negative-test invalid-point vectors switched from
  Edwards25519-specific cases to RFC 9496 §4.3.1 rejection categories
  (high-bit-set, non-canonical field element).

---

## What Reza needs to do

1. Add `require github.com/gtank/ristretto255 v0.1.2` to `go.mod`, then
   `go mod tidy`.
2. Run `bash apply_patch_b.sh` from the SP root (or apply the imports by
   hand using `sed -i 's#github.com/your-org/sp#upspa#g'` etc.).
3. `go test ./internal/crypto/...` — all suites including the existing
   week-1/2/3 tests, fuzz tests, and negative tests should pass.

`internal/api/`, `internal/db/`, `cmd/sp/`, and the Rust client are
**untouched**. This patch is purely on `internal/crypto/`.

---

## What this does *not* fix (still needs Reza's attention)

These are out of scope for my package, but were observed while wiring
up the integration test harness, so flagging here for completeness:

- `internal/api/setup.go` — `DefaultCryptoHelper.VerifyEd25519` returns
  `true` unconditionally instead of calling `crypto.VerifyEd25519`.
- `internal/api/toprf.go` — line 47 returns a hardcoded mock string
  instead of calling `crypto.RistrettoScalarMult`.
- `internal/api/pwd_update.go` — line 70 builds the signature message as
  the literal string `"mock_signature_message_payload"` instead of
  calling `crypto.BuildPwdUpdateSigMsg(...)`.
- `crates/upspa-core/src/protocol/password_update.rs` — `K0` from the old
  cipherid plaintext is carried forward unchanged into `cid_new`. This is
  a security-model question rather than an implementation bug — flagging
  for hocas to confirm intended behaviour against the paper's threat model.
