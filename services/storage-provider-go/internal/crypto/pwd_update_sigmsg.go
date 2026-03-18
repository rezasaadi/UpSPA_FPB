// Package crypto provides cryptographic helpers for the Storage Provider service.
//
// Week 3: Extracted BuildPwdUpdateSigMsg into its own file and validated the
// byte layout against docs/protocol-phases.md. See efe-week3.md for details.

package crypto

import (
	"encoding/binary"
)

// BuildPwdUpdateSigMsg constructs the exact byte sequence that the client
// signs during a password-update request.
//
// Layout (from docs/protocol-phases.md):
//
//	[cidNonce (24 B)] || [cidCt (var)] || [cidTag (16 B)] || [kINew (32 B)] || [ts (8 B, u64 LE)] || [spID (4 B, u32 LE)]
//
// Fixed-length summary (with empty cidCt):
//
//	Offset  0 – 23   cidNonce     (LenCtBlobNonce = 24)
//	Offset 24 – 23+n cidCt        (variable, n = len(cidCt))
//	Offset 24+n – 39+n cidTag     (LenCtBlobTag   = 16)
//	Offset 40+n – 71+n kINew      (LenScalarKi    = 32)
//	Offset 72+n – 79+n timestamp  (8 bytes, little-endian uint64)
//	Offset 80+n – 83+n spID       (4 bytes, little-endian uint32)
//	Total:  84 + n bytes
//
// All inputs are raw bytes (already decoded from base64url-no-pad).
// tsU64LE and spIDU32LE are passed as Go integers; this function encodes
// them as little-endian bytes to match the client's signing format.
//
// Callers are responsible for validating individual field lengths using
// DecodeFixedB64 with the Len* constants before calling this function.
//
// NOTE: do NOT log the return value — it contains key material (kINew).
func BuildPwdUpdateSigMsg(
	cidNonce  []byte, // LenCtBlobNonce = 24 bytes
	cidCt     []byte, // variable length
	cidTag    []byte, // LenCtBlobTag   = 16 bytes
	kINew     []byte, // LenScalarKi    = 32 bytes
	tsU64LE   uint64,
	spIDU32LE uint32,
) []byte {
	// Encode the integer fields as little-endian byte slices.
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, tsU64LE)

	spIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(spIDBytes, spIDU32LE)

	// Pre-allocate the exact output capacity to avoid reallocation.
	totalLen := len(cidNonce) + len(cidCt) + len(cidTag) + len(kINew) + 8 + 4
	msg := make([]byte, 0, totalLen)

	// Append fields in wire order.
	msg = append(msg, cidNonce...)  // offset 0
	msg = append(msg, cidCt...)    // offset LenCtBlobNonce
	msg = append(msg, cidTag...)   // offset LenCtBlobNonce + len(cidCt)
	msg = append(msg, kINew...)    // offset LenCtBlobNonce + len(cidCt) + LenCtBlobTag
	msg = append(msg, tsBytes...)  // offset LenCtBlobNonce + len(cidCt) + LenCtBlobTag + LenScalarKi
	msg = append(msg, spIDBytes...) // offset LenCtBlobNonce + len(cidCt) + LenCtBlobTag + LenScalarKi + 8

	return msg
}
