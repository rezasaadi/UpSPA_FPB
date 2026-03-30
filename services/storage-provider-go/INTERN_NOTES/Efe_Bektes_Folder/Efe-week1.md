# Efe — Week 1 Notes

**Branch:** `intern/efe/...`  
**Package:** `internal/crypto/**`

## What I did
Spent most of the week reading up on the crypto concepts involved — base64url encoding, Ed25519, Ristretto255, and TOPRF. I'm still getting comfortable with these topics.
With significant AI assistance, I produced template implementations for all five functions required by the shared contract in `Baseline.md`:
- `CanonicalB64` / `DecodeFixedB64` — base64url-no-pad canonicalization
- `VerifyEd25519` — signature verification
- `RistrettoScalarMult` — TOPRF scalar multiplication
- `BuildPwdUpdateSigMsg` — password-update signature message layout
Each has a corresponding `_test.go` file and there is a `README.md` for the package.

## Honest notes
The code was largely AI-generated and reviewed/adjusted by me. I understand the high-level purpose of each function but I'm still working on fully understanding the underlying math, especially Ristretto255 and TOPRF. Will dig deeper in Week 2.

## Open questions
- Need to verify `BuildPwdUpdateSigMsg` byte layout against `docs/protocol-phases.md`.
- `go.mod` module path is a placeholder — needs updating to the real repo path.

## Next week
- Verify and fix anything wrong in the implementations now that I understand the concepts better.
- Write fuzz tests for the base64 helpers.
- Be available to help Emirhan use the crypto functions in the API layer.
