# Efe — Week 4 Notes

**Branch:** `intern/efe/...`  
**Package:** `internal/crypto/**`


## What is done

Week 4 focus: complete the negative test suite, add fuzz tests for the base64
helpers, and write this security note. Running the tests against the real
library exposed two additional bugs in the Week 2/3 test code that were fixed
here.


## Bugs found and fixed (Week 4 testing)

### Bug 3 — `ristretto_test.go`: wrong invalid-point vector (`0xFF*32`)

**Severity:** Medium — test gives false confidence (same class as Bug 2, Week 2)

`TestRistrettoScalarMult_InvalidPoint` used `bytes.Repeat([]byte{0xFF}, 32)` as
the "invalid" point. Running against `filippo.io/edwards25519 v1.1.0` shows this
encoding is **accepted** — it decodes to a valid curve point. The test was
passing only when the library happened to reject it; against the real version it
silently passed with no error, meaning the test provided zero coverage.

**Probe results (partial):**
```
all 0xFF    → ACCEPTED   ← was used as "invalid", WRONG
all 0x80    → ACCEPTED
all 0x02    → REJECTED   ← correct test vector
all 0x7F    → REJECTED   ← correct test vector
last = 0x01 → REJECTED   ← correct test vector
last = 0xE0 → REJECTED   ← already used, correct
```

**Fix:** Replaced `0xFF*32` with `0x02*32` in `ristretto_test.go`.
Updated `negative_test.go` to use `{0x02*32, 0x7F*32, last=0x01, last=0xE0}`.

### Bug 4 — `negative_test.go`: wrong whitespace rejection assumptions (Go 1.22)

**Severity:** Low — test fails on target Go version

`TestCanonicalB64_Negative_EmbeddedWhitespace` expected `\n` and `\r\n` to
return `ErrInvalidBase64`. In Go 1.22, `base64.RawURLEncoding.DecodeString`
was updated to **silently skip `\n` and `\r\n`** (treating them as ignorable
whitespace, consistent with PEM/MIME conventions). Space and tab are still
rejected.

This means `"dGVz\ndA"` decodes to `"test"` just as `"dGVzdA"` does — the
canonicalization is correct, but we cannot treat newlines as an error.

**Fix:** Removed `\n` and `\r\n` from the negative whitespace test cases.
Added a comment explaining the Go 1.22 behavior so future maintainers know
this is intentional.

---

## Files changed / added

| File | Change |
|---|---|
| `internal/crypto/ristretto_test.go` | **Fixed** — invalid-point test vector (Bug 3) |
| `internal/crypto/negative_test.go` | **New** — expanded negative test suite (Bug 4 fix + full coverage) |
| `internal/crypto/fuzz_test.go` | **New** — fuzz tests for `CanonicalB64` and `DecodeFixedB64` |
| `INTERN_NOTES/efe-week4.md` | This file |

---

## Fuzz tests (`fuzz_test.go`)

Two fuzz targets:

**`FuzzCanonicalB64`** — verifies two invariants for any string input:
1. If decoding succeeds, the canonical string must re-decode to the same bytes
   (round-trip correctness).
2. Canonicalization is idempotent: `canon(canon(x)) == canon(x)`.

**`FuzzDecodeFixedB64`** — verifies that when the function succeeds, the
returned slice has exactly `n` bytes.

Run them with:
```bash
go test -fuzz=FuzzCanonicalB64    ./internal/crypto/... -fuzztime=60s
go test -fuzz=FuzzDecodeFixedB64  ./internal/crypto/... -fuzztime=60s
```

---

## Expanded negative tests (`negative_test.go`)

Coverage by category:

### Malformed base64
- Standard base64 `+` / `/` chars rejected
- Embedded whitespace (space, tab, newline, CRLF, leading/trailing)
- Null bytes
- Non-ASCII (high-byte) characters
- `ErrInvalidBase64` returned in every case

### Wrong lengths for every wire-protocol field
Tested for `DecodeFixedB64` with off-by-one and grossly wrong lengths:

| Field | Tested bad lengths |
|---|---|
| `LenEd25519PublicKey` (32) | 0, 1, 16, 31, 33, 48, 64 |
| `LenEd25519Signature` (64) | 0, 1, 32, 63, 65, 128 |
| `LenCtBlobNonce` (24) | 0, 1, 16, 23, 25, 32 |
| `LenCtBlobTag` (16) | 0, 1, 8, 15, 17, 32 |
| `LenRistretto` (32) | 0, 1, 16, 31, 33, 64 |
| `LenScalarKi` (32) | 0, 1, 16, 31, 33, 64 |

### Invalid Ristretto255 point encodings
`ErrInvalidPoint` for: `0xFF*32`, `0x80*32`, last-byte `0x80`, last-byte `0xE0`.

### Invalid (non-canonical) scalar encodings
`ErrInvalidScalar` for: `0xFF*32`, `0x7F*32`, group order `l`, and `l+1`.

### `VerifyEd25519` panic guards
Confirmed panics for sigPk=31 bytes, sigPk=33 bytes, sig=63 bytes, sig=65 bytes.

---

## Security note

### Why canonical base64url-no-pad encoding matters

The same raw bytes can be encoded as multiple valid base64 strings (padded,
unpadded, different alphabets). If the server stores one form and later compares
against another, the comparison silently fails even for a correct value. Worse,
a replay-protection check comparing `stored_canon == incoming_canon` is
trivially bypassed if the attacker re-encodes a previously rejected value in a
different form.

`CanonicalB64` fixes this: decode to raw bytes, re-encode with
`base64.RawURLEncoding`. Every subsequent comparison and DB uniqueness constraint
operates on exactly one representation per byte sequence.

### Why signature bytes must be exact

`BuildPwdUpdateSigMsg` produces the exact byte sequence the client signs. If
any field is in the wrong position, has the wrong length, or uses the wrong
byte order, `VerifyEd25519` will reject every legitimate password-update request
while silently accepting none.

Key consequences of getting this wrong:
- **Wrong field order** → every real request rejected; no forged request accepted.
- **Wrong timestamp endianness** → monotonic replay protection broken (the SP
  stores a value it cannot correctly compare against future timestamps).
- **Missing `sp_id`** → a valid signature for SP-1 is accepted at SP-2 (cross-SP
  replay).
- **Missing `kINew`** → an attacker can swap the stored `k_i` for a key they
  control without re-signing.

The golden vector test in `pwd_update_sigmsg_test.go` pins the entire message
byte-by-byte so any layout regression is caught immediately.

### What must never be logged

| Value | Why |
|---|---|
| `uid`, `suid` | User identity; enables linkability |
| `k_i` / `kINew` | Partial TOPRF key material |
| `blinded` (TOPRF input) | Client's blinded password |
| `y` (TOPRF output) | Combined with client data reconstructs the password |
| `cid` / `cj` raw bytes | Encrypted secret shares; must stay opaque |
| Ed25519 signatures | Replay risk |
| Return value of `BuildPwdUpdateSigMsg` | Contains `kINew` |

The threat model assumes a potentially malicious SP (see §3 of the paper).
Protecting against a compromised log pipeline is a baseline requirement.

---

## Open items resolved

- [x] Fuzz tests (carried from Week 3)
- [x] `crypto.go` cleanup (carried from Week 3)
- [x] Expanded negative test suite
- [x] Security note

## Still open (for team)

- `go.mod` module path updated to `github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go` ✓
- Run `go mod tidy` after cloning to regenerate `go.sum`.
- Baseline.md should add `GenerateScalarKi()` to the `internal/crypto`
  interface section so the setup handler knows to call it.
- Sina: confirm `k_i_b64` in the DB is always the output of `GenerateScalarKi()`
  encoded via `CanonicalB64`, never raw `rand.Read(32)` bytes.
