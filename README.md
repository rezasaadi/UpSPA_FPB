# `internal/crypto`

> **Owner:** Efe Bekteş — `intern/efe/...`  
> **Week 1 status:** Underlying cryptography concepts skimmed; AI-assisted template code written and structured.

---

## Overview

This package provides all low-level cryptographic helpers for the Storage Provider (SP) service. No other package should import raw crypto primitives directly — everything goes through the functions here.

---

## Files

| File | What it does |
|---|---|
| `b64.go` | Canonical base64url-no-pad encoding/decoding + byte-length constants |
| `ed25519.go` | Ed25519 signature verification |
| `ristretto.go` | Ristretto255 scalar multiplication (TOPRF evaluation) |
| `pwd_update_sigmsg.go` | Password-update signature message construction |
| `b64_test.go` | Tests for base64 helpers |
| `ed25519_test.go` | Tests for Ed25519 verification |
| `ristretto_test.go` | Tests for Ristretto scalar multiplication |
| `pwd_update_sigmsg_test.go` | Tests for signature message layout |

---

## Public API

### Base64 (`b64.go`)

```go
// Decodes any base64url string and re-encodes to canonical no-pad form.
CanonicalB64(s string) (canon string, raw []byte, err error)

// Like CanonicalB64, but also enforces an exact byte length n.
DecodeFixedB64(s string, n int) (raw []byte, canon string, err error)
```

**Byte-length constants** (use with `DecodeFixedB64`):

| Constant | Value | Used for |
|---|---|---|
| `LenEd25519PublicKey` | 32 | Ed25519 public key |
| `LenEd25519Signature` | 64 | Ed25519 signature |
| `LenCtBlobNonce` | 24 | Ciphertext blob nonce |
| `LenCtBlobTag` | 16 | Ciphertext blob tag |
| `LenRistretto` | 32 | Ristretto255-encoded point |
| `LenScalarKi` | 32 | TOPRF scalar share k_i |

---

### Ed25519 (`ed25519.go`)

```go
// Returns true if sig is a valid Ed25519 signature over msg by sigPk.
// sigPk must be 32 bytes, sig must be 64 bytes — panics otherwise.
// Always call DecodeFixedB64 with the correct Len* constant before calling this.
VerifyEd25519(sigPk []byte, msg []byte, sig []byte) bool
```

---

### Ristretto255 (`ristretto.go`)

```go
// Computes y = k * blinded (TOPRF evaluation).
// k: 32-byte scalar (k_i share), blinded: 32-byte Ristretto255 point.
// Returns y as a 32-byte Ristretto255-encoded point.
RistrettoScalarMult(k []byte, blinded []byte) (y []byte, err error)
```

Errors returned: `ErrWrongLength`, `ErrInvalidPoint`.

---

### Password-update signature message (`pwd_update_sigmsg.go`)

```go
// Constructs the exact byte sequence the client signs on password update.
BuildPwdUpdateSigMsg(
    cidNonce   []byte,  // 24 bytes
    cidCt      []byte,  // variable
    cidTag     []byte,  // 16 bytes
    kINew      []byte,  // 32 bytes
    tsU64LE    uint64,
    spIDU32LE  uint32,
) []byte
```

**Message layout:**

```
[ cidNonce (24) ][ cidCt (var) ][ cidTag (16) ][ kINew (32) ][ ts (8, u64 LE) ][ spID (4, u32 LE) ]
```

---

## Error Sentinel Values

```go
var ErrInvalidBase64 = errors.New("invalid_base64")
var ErrWrongLength   = errors.New("wrong_byte_length")
var ErrInvalidPoint  = errors.New("invalid_ristretto_point")
```

Use `errors.Is(err, crypto.ErrWrongLength)` etc. in handlers to map to the correct HTTP status code (400).

---

## Security Rules

- **Never log** `uid`, `suid`, `cid`, `cj`, `k_i`, signatures, or curve points — not even in debug mode.
- All incoming base64 fields must be decoded and **re-encoded to canonical form** before storage or comparison.
- Wrong byte lengths must cause the **caller to return HTTP 400**.
- The SP must **never decrypt or interpret** `cid` / `cj` — it stores `{nonce, ct, tag}` as opaque blobs.

---

## Dependency

```
filippo.io/edwards25519 v1.1.0
```

Run `go mod tidy` after adding to `go.mod` to generate `go.sum`.

---

## Running Tests

```bash
go test ./internal/crypto/...
```

All functions have corresponding `_test.go` files. Tests cover valid inputs, invalid inputs, wrong lengths, wrong keys, and little-endian byte layout verification.

---

## References

- [encoding/base64 (Go stdlib)](https://pkg.go.dev/encoding/base64)
- [RFC 4648 — Base64 encoding](https://datatracker.ietf.org/doc/html/rfc4648)
- [crypto/ed25519 (Go stdlib)](https://pkg.go.dev/crypto/ed25519)
- [RFC 8032 — Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)
- [Ristretto255](https://ristretto.group/)
- [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519)
