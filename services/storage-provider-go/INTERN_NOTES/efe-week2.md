# Efe — Week 2 Notes

**Branch:** `intern/efe/...`  
**Package:** `internal/crypto/**`

---

## What I did

Reviewed the Week 1 template code more carefully now that I understand the underlying math better. Found and fixed two real bugs — both in the Ristretto/TOPRF code — and expanded the test suite accordingly.

---

## Bugs found and fixed

### Bug 1 — `ristretto.go`: wrong scalar decoding method (`SetBytesWithClamping`)

**File:** `internal/crypto/ristretto.go`  
**Severity:** Critical — protocol-breaking, silent wrong value

The Week 1 code decoded the TOPRF scalar `k_i` using `(*Scalar).SetBytesWithClamping`. This method is designed for Ed25519/X25519 private keys: it clears bits 0, 1, 2, and 255 of the input bytes before treating them as a scalar. Applied to a TOPRF share, it silently computes:

```
y = clamp(k_i) * blinded    ← WRONG
```

instead of:

```
y = k_i * blinded            ← CORRECT
```

The result is a wrong TOPRF evaluation value with no error returned. Any downstream OPRF verification against the correct `k_i` would silently fail or produce an incorrect output.

**Fix:** Replaced with `(*Scalar).SetCanonicalBytes`, which decodes a fully-reduced scalar in [0, l) and returns an error if the value is out of range (i.e. `k_i >= l`). Added a new sentinel error `ErrInvalidScalar` so callers can map this to HTTP 400.

```go
// Before (WRONG):
scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(k)

// After (CORRECT):
scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(k)
if err != nil {
    return nil, fmt.Errorf("%w: %w", ErrInvalidScalar, err)
}
```

**Implication for k_i generation:** `SetCanonicalBytes` requires the scalar to be in `[0, l)`. The component that generates `k_i` (likely Sina's DB layer or a key-generation utility) must ensure the value is fully reduced. If it is generated as raw random bytes it must be reduced modulo `l` before storage.

---

### Bug 2 — `ristretto_test.go`: wrong "invalid point" test input

**File:** `internal/crypto/ristretto_test.go`  
**Severity:** Medium — test gives false confidence

The Week 1 test `TestRistrettoScalarMult_InvalidPoint` used `make([]byte, 32)` (all-zeros) as the "invalid" point, with the comment `// all-zero is not a valid Ristretto255 point`.

This is factually incorrect. In Ristretto255, the all-zeros 32-byte encoding **is** the identity element — a perfectly valid group element. The test was either passing by coincidence (if the library happened to reject identity) or would fail silently across versions.

**Fix:** Replaced with `bytes.Repeat([]byte{0xFF}, 32)`, which encodes a value that is not a valid Ristretto255 point. Added a separate regression test `TestRistrettoScalarMult_IdentityPoint_IsValid` that explicitly asserts the identity point is accepted, documenting the intended behavior.

---

## Tests added / changed

| Test | Change | Reason |
|---|---|---|
| `TestRistrettoScalarMult_InvalidPoint` | Changed input from `0x00*32` to `0xFF*32` | All-zeros is the valid identity encoding |
| `TestRistrettoScalarMult_InvalidScalar` | **New** | Covers the new `ErrInvalidScalar` path |
| `TestRistrettoScalarMult_IdentityPoint_IsValid` | **New** | Regression: documents that identity is valid |
| `TestRistrettoScalarMult_ValidInputs` | Added `k[31] &= 0x0f` | Random bytes can be >= l; must be canonical |
| `TestRistrettoScalarMult_Deterministic` | Same clamping fix | Same reason |
| `TestRistrettoScalarMult_DifferentKeys_DifferentOutputs` | Use fixed small scalars (1, 2) instead of `rand.Read` | Deterministic, always canonical, no flakiness |

---

## Files changed

- `internal/crypto/ristretto.go` — scalar decoding fix + new `ErrInvalidScalar` sentinel
- `internal/crypto/ristretto_test.go` — invalid-point fix + new tests

No changes to `b64.go`, `ed25519.go`, `pwd_update_sigmsg.go`, or their tests — those were correct.

---

## New file added: `scalar_keygen.go`

After reading the reference papers (Acar et al. 2013, İşler & Küpçü 2017) and RFC 9497, I realized the k_i generation problem mentioned in the Bug 1 follow-up is a crypto-package responsibility, not just a note for other layers. I added `GenerateScalarKi()` to the crypto package.

**Why this belongs here:** The papers specify `k_i ← OPRFKeyGen(1^λ)`. RFC 9497 §2.1 says the OPRF key must be a uniformly random, non-zero scalar. The correct way to generate it in filippo.io/edwards25519 is `(*Scalar).SetUniformBytes(64_bytes)` — 64 uniform random bytes fed through a wide reduction mod l. This guarantees a canonical result with no bias and no rejection-retry loop. Any other approach (raw 32 bytes, clamping) is either broken or biased.

**Impact:** If Sina's DB code or Emirhan's setup handler generates k_i as raw `rand.Read(32_bytes)`, approximately half of all generated keys will be `>= l` and will be rejected by `RistrettoScalarMult` at eval time, causing spurious 400 errors for real users. Using `GenerateScalarKi()` eliminates this entirely.

---

## Paper-derived insights for the whole team

After reading the research papers carefully in the context of this codebase, here are insights relevant to each layer.

### The TOPRF flow in context (Threshold SPA, Fig. 3)

The SP's complete role in the OPRF evaluation is:
1. Receive `storUID` (= `suid`) and a `blinded` point from the client.
2. Look up `k_i` for that `suid`.
3. Return `y = k_i * blinded` — exactly what `RistrettoScalarMult(k_i, blinded)` computes.

Nothing more. The SP never sees the password, never sees the unblinded OPRF output, and never reconstructs any secret. This is the entire reason `RistrettoScalarMult` is the central function of this package.

### Why the SP must never decrypt `cid` (Baseline.md rule explained)

The paper (registration phase) shows `c_i ← Enc_{F_{k_i}(pwd)}(s_i)`. The `cid` blob stored at the SP is exactly this ciphertext — an encryption of a secret share under the OPRF output. If the SP could decrypt it, it would learn the share `s_i`. With the login server's data, `t` colluding SPs could then reconstruct the original secret and run offline dictionary attacks. This is precisely the threat model the protocol is designed to prevent. The "opaque blob" rule in `Baseline.md` is not arbitrary — it is a direct security requirement.

### `suid` is domain-scoped (relevant to Sina + Emirhan)

The paper specifies `storUID_i = H(userID || ls)` where `ls` is the login-server domain. In our system `suid` plays this role. It must be treated as an opaque identifier by the SP — the SP should never interpret, log, or infer the underlying `userID` or domain from it. This is also why the non-logging rule applies to `suid`.

### Password-update signature message layout explained

`BuildPwdUpdateSigMsg` constructs the byte sequence the client signs to authorize a password update. The commitment covers:
- The **new** `cid` blob `(nonce || ct || tag)` — binds the signature to the exact new encrypted share.
- The **new** `k_i` — binds the signature to the exact new OPRF key.
- `timestamp` — provides replay protection (monotonic, stored as `last_pwd_update_time`).
- `sp_id` — prevents cross-SP replay (signature valid only at this specific SP).

If any field were missing, an attacker who intercepted a valid password-update request could replay or modify it. The layout in `pwd_update_sigmsg.go` is correct and complete.

---

## Open questions / follow-ups

- **Fuzz tests:** planned for Week 3/4 — will add `FuzzCanonicalB64` and `FuzzDecodeFixedB64` in `b64_test.go`.
- **`go.mod` module path:** still a placeholder (`github.com/your-org/sp`). Needs updating to the real repo path before integration.
- **Baseline.md update:** `GenerateScalarKi()` should be added to the shared contract's `internal/crypto` interface section so Emirhan's setup handler knows to call it.

---

## Next week (Week 3)

- Verify `BuildPwdUpdateSigMsg` byte layout against `docs/protocol-phases.md` (was deferred from Week 1).
- Write fuzz tests for base64 helpers.
- Be available for Emirhan to integrate `crypto.*` into the API layer and answer questions about error mapping (e.g. `ErrInvalidScalar` → HTTP 400).
- Coordinate with Sina to confirm `k_i_b64` is stored as the output of `GenerateScalarKi()` (base64url-no-pad encoded) and never as raw random bytes.
