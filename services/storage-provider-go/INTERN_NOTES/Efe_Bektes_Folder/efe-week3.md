# Efe — Week 3 Notes

**Branch:** `intern/efe/...`  
**Package:** `internal/crypto/**`

---

## What I did

Week 3 focus was the password-update signature message — confirming the layout,
hardening the tests, and completing the stretch goal of consolidating all
field-length constants.

---

## Files changed / added

| File | Change |
|---|---|
| `internal/crypto/pwd_update_sigmsg.go` | Extracted from `crypto.go`; added per-field offset comments |
| `internal/crypto/pwd_update_sigmsg_test.go` | Full rewrite — every field now has an independent offset test |
| `internal/crypto/constants.go` | **New** — single source of truth for all `Len*` constants |

The implementation in `BuildPwdUpdateSigMsg` was already correct from Week 1.
Week 3 work was extraction, documentation, and test coverage.

---

## Layout confirmed

```
Offset  0       cidNonce     LenCtBlobNonce = 24 bytes
Offset 24       cidCt        variable (len n)
Offset 24+n     cidTag       LenCtBlobTag   = 16 bytes
Offset 40+n     kINew        LenScalarKi    = 32 bytes
Offset 72+n     timestamp    LenTimestamp   =  8 bytes, little-endian uint64
Offset 80+n     spID         LenSpID        =  4 bytes, little-endian uint32
Total:           84 + n bytes
```

When `cidCt` is empty the total is exactly `PwdUpdateSigMsgFixedLen = 84` bytes.

---

## Tests added (pwd_update_sigmsg_test.go)

Previously the only tests were in `crypto_test.go` and checked:
- total length (one case)
- nonce at offset 0
- ct follows nonce
- timestamp little-endian (one case)

Week 3 test suite now covers:

| Test | What it pins |
|---|---|
| `TestBuildPwdUpdateSigMsg_TotalLength_EmptyCt` | 84 bytes when ct=[] |
| `TestBuildPwdUpdateSigMsg_TotalLength_NonEmptyCt` | 84+n bytes for ct of length n |
| `TestBuildPwdUpdateSigMsg_Nonce_Offset` | cidNonce at offset 0 |
| `TestBuildPwdUpdateSigMsg_Ct_Offset` | cidCt at offset 24 |
| `TestBuildPwdUpdateSigMsg_Ct_Empty` | empty ct → tag immediately follows nonce |
| `TestBuildPwdUpdateSigMsg_Tag_Offset` | cidTag at offset 24+n |
| `TestBuildPwdUpdateSigMsg_KiNew_Offset` | kINew at offset 40+n |
| `TestBuildPwdUpdateSigMsg_Timestamp_LittleEndian` | ts at offset 72+n, correct LE encoding |
| `TestBuildPwdUpdateSigMsg_Timestamp_KnownBytes` | ts=0x0102…0708 → raw bytes 08 07 … 01 |
| `TestBuildPwdUpdateSigMsg_Timestamp_Zero` | ts=0 → 8 zero bytes |
| `TestBuildPwdUpdateSigMsg_SpID_LittleEndian` | spID at offset 80+n, correct LE encoding |
| `TestBuildPwdUpdateSigMsg_SpID_KnownBytes` | spID=0x0A0B0C0D → raw bytes 0D 0C 0B 0A |
| `TestBuildPwdUpdateSigMsg_SpID_Zero` | spID=0 → 4 zero bytes |
| `TestBuildPwdUpdateSigMsg_GoldenVector` | full message compared byte-by-byte to hand-computed value |
| `TestBuildPwdUpdateSigMsg_NoAlias` | mutating inputs after call does not change returned message |

Every field now has an independent pinned test. The golden vector test pins the
entire message at once as a regression anchor.

---

## Stretch: constants.go

Moved all `Len*` constants out of `crypto.go` and into a dedicated
`constants.go`. Added two new derived constants:

- `LenTimestamp = 8` — the 8-byte little-endian uint64 timestamp in the sig message
- `LenSpID = 4` — the 4-byte little-endian uint32 SP identifier
- `PwdUpdateSigMsgFixedLen = 84` — total length when cidCt is empty

**Why this matters:** Before this change, `crypto.go`, the test file, and
future API handler code would all embed the magic numbers `8` and `4` for
timestamp and spID. With named constants, a layout change is a one-line
edit in `constants.go` and the compiler will find all uses.

**Impact on other layers:**  
Emirhan's API handlers can now import `crypto.PwdUpdateSigMsgFixedLen` to
pre-validate that a reconstructed message has at least the minimum expected
length before passing it to `VerifyEd25519`.

---

## Open questions / follow-ups

- **`crypto.go` cleanup:** `BuildPwdUpdateSigMsg` and the `Len*` constants
  should be removed from `crypto.go` now that they live in their own files.
  Left for a clean-up PR to avoid breaking Emirhan's in-flight branch.
- **Fuzz tests:** `FuzzCanonicalB64` and `FuzzDecodeFixedB64` pushed to Week 4
  (same as last week).
- **`go.mod` path:** still `github.com/your-org/sp` — needs the real repo path
  before the final merge.

---

## Next week (Week 4)

- Fuzz tests for `CanonicalB64` / `DecodeFixedB64`.
- Clean up `crypto.go` (remove extracted symbols).
- Support integration: answer Emirhan's questions about `ErrInvalidScalar` →
  HTTP 400 mapping and how to use `PwdUpdateSigMsgFixedLen` in the handler.
- Confirm with Sina that `k_i_b64` in the DB is always the output of
  `GenerateScalarKi()` encoded via `CanonicalB64`, never raw random bytes.
