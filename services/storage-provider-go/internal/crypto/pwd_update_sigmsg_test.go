// Week 3: Dedicated test file for BuildPwdUpdateSigMsg.
//
// Tests verify the exact byte layout documented in pwd_update_sigmsg.go
// using fixed sample bytes so every field offset is pinned independently.
// No randomness is used — all values are chosen so expected bytes are trivial
// to reason about without running the code.

package crypto_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/your-org/sp/internal/crypto"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fixedMsg builds a BuildPwdUpdateSigMsg call with fully deterministic,
// distinct-pattern inputs so individual field offsets can be asserted.
//
// Field byte patterns (all non-overlapping values):
//
//	cidNonce  = 0x01 * 24
//	cidCt     = caller-supplied  (variable)
//	cidTag    = 0x03 * 16
//	kINew     = 0x04 * 32
//	tsU64LE   = 0x0102030405060708
//	spIDU32LE = 0x0A0B0C0D
func fixedMsg(ct []byte) ([]byte, int) {
	nonce := bytes.Repeat([]byte{0x01}, crypto.LenCtBlobNonce)
	tag := bytes.Repeat([]byte{0x03}, crypto.LenCtBlobTag)
	ki := bytes.Repeat([]byte{0x04}, crypto.LenScalarKi)
	ts := uint64(0x0102030405060708)
	spID := uint32(0x0A0B0C0D)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, ts, spID)
	return msg, len(ct)
}

// offsets returns the start offset of each field given len(cidCt) = n.
func offsets(n int) (nonce, ct, tag, ki, ts, spID int) {
	nonce = 0
	ct = nonce + crypto.LenCtBlobNonce
	tag = ct + n
	ki = tag + crypto.LenCtBlobTag
	ts = ki + crypto.LenScalarKi
	spID = ts + 8
	return
}

// ---------------------------------------------------------------------------
// total length
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_TotalLength_EmptyCt(t *testing.T) {
	msg, _ := fixedMsg([]byte{})
	// 24 + 0 + 16 + 32 + 8 + 4 = 84
	want := crypto.LenCtBlobNonce + crypto.LenCtBlobTag + crypto.LenScalarKi + 8 + 4
	if len(msg) != want {
		t.Errorf("want %d bytes, got %d", want, len(msg))
	}
}

func TestBuildPwdUpdateSigMsg_TotalLength_NonEmptyCt(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 48)
	msg, n := fixedMsg(ct)
	want := crypto.LenCtBlobNonce + n + crypto.LenCtBlobTag + crypto.LenScalarKi + 8 + 4
	if len(msg) != want {
		t.Errorf("want %d bytes, got %d", want, len(msg))
	}
}

// ---------------------------------------------------------------------------
// field: cidNonce (offset 0, length 24)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_Nonce_Offset(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	oNonce, _, _, _, _, _ := offsets(n)

	got := msg[oNonce : oNonce+crypto.LenCtBlobNonce]
	want := bytes.Repeat([]byte{0x01}, crypto.LenCtBlobNonce)
	if !bytes.Equal(got, want) {
		t.Errorf("cidNonce at offset %d: got %x, want %x", oNonce, got, want)
	}
}

// ---------------------------------------------------------------------------
// field: cidCt (offset 24, variable length)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_Ct_Offset(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	_, oCt, _, _, _, _ := offsets(n)

	got := msg[oCt : oCt+n]
	if !bytes.Equal(got, ct) {
		t.Errorf("cidCt at offset %d: got %x, want %x", oCt, got, ct)
	}
}

func TestBuildPwdUpdateSigMsg_Ct_Empty(t *testing.T) {
	// Empty cidCt must still produce valid output; tag must immediately follow nonce.
	msg, n := fixedMsg([]byte{})
	_, _, oTag, _, _, _ := offsets(n)
	if oTag != crypto.LenCtBlobNonce {
		t.Errorf("with empty ct, tag offset should be %d, got %d",
			crypto.LenCtBlobNonce, oTag)
	}
	got := msg[oTag : oTag+crypto.LenCtBlobTag]
	want := bytes.Repeat([]byte{0x03}, crypto.LenCtBlobTag)
	if !bytes.Equal(got, want) {
		t.Errorf("cidTag (empty ct): got %x, want %x", got, want)
	}
}

// ---------------------------------------------------------------------------
// field: cidTag (offset 24+n, length 16)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_Tag_Offset(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	_, _, oTag, _, _, _ := offsets(n)

	got := msg[oTag : oTag+crypto.LenCtBlobTag]
	want := bytes.Repeat([]byte{0x03}, crypto.LenCtBlobTag)
	if !bytes.Equal(got, want) {
		t.Errorf("cidTag at offset %d: got %x, want %x", oTag, got, want)
	}
}

// ---------------------------------------------------------------------------
// field: kINew (offset 24+n+16, length 32)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_KiNew_Offset(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	_, _, _, oKi, _, _ := offsets(n)

	got := msg[oKi : oKi+crypto.LenScalarKi]
	want := bytes.Repeat([]byte{0x04}, crypto.LenScalarKi)
	if !bytes.Equal(got, want) {
		t.Errorf("kINew at offset %d: got %x, want %x", oKi, got, want)
	}
}

// ---------------------------------------------------------------------------
// field: timestamp (offset 24+n+16+32, length 8, little-endian uint64)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_Timestamp_LittleEndian(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	_, _, _, _, oTs, _ := offsets(n)

	got := msg[oTs : oTs+8]
	ts := uint64(0x0102030405060708)
	want := make([]byte, 8)
	binary.LittleEndian.PutUint64(want, ts)
	// little-endian: LSB first → 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	if !bytes.Equal(got, want) {
		t.Errorf("timestamp at offset %d: got %x, want %x", oTs, got, want)
	}
}

func TestBuildPwdUpdateSigMsg_Timestamp_KnownBytes(t *testing.T) {
	// Belt-and-suspenders: assert the raw expected bytes directly.
	ct := []byte{}
	msg, n := fixedMsg(ct)
	_, _, _, _, oTs, _ := offsets(n)

	wantBytes := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	got := msg[oTs : oTs+8]
	if !bytes.Equal(got, wantBytes) {
		t.Errorf("timestamp bytes (empty ct): got %x, want %x", got, wantBytes)
	}
}

func TestBuildPwdUpdateSigMsg_Timestamp_Zero(t *testing.T) {
	nonce := make([]byte, crypto.LenCtBlobNonce)
	tag := make([]byte, crypto.LenCtBlobTag)
	ki := make([]byte, crypto.LenScalarKi)
	msg := crypto.BuildPwdUpdateSigMsg(nonce, nil, tag, ki, 0, 0)

	oTs := crypto.LenCtBlobNonce + crypto.LenCtBlobTag + crypto.LenScalarKi
	got := msg[oTs : oTs+8]
	want := make([]byte, 8) // all zeros for ts=0
	if !bytes.Equal(got, want) {
		t.Errorf("timestamp=0: got %x, want %x", got, want)
	}
}

// ---------------------------------------------------------------------------
// field: spID (offset 24+n+16+32+8, length 4, little-endian uint32)
// ---------------------------------------------------------------------------

func TestBuildPwdUpdateSigMsg_SpID_LittleEndian(t *testing.T) {
	ct := bytes.Repeat([]byte{0x02}, 18)
	msg, n := fixedMsg(ct)
	_, _, _, _, _, oSpID := offsets(n)

	got := msg[oSpID : oSpID+4]
	spID := uint32(0x0A0B0C0D)
	want := make([]byte, 4)
	binary.LittleEndian.PutUint32(want, spID)
	// little-endian: 0x0D, 0x0C, 0x0B, 0x0A
	if !bytes.Equal(got, want) {
		t.Errorf("spID at offset %d: got %x, want %x", oSpID, got, want)
	}
}

func TestBuildPwdUpdateSigMsg_SpID_KnownBytes(t *testing.T) {
	ct := []byte{}
	msg, n := fixedMsg(ct)
	_, _, _, _, _, oSpID := offsets(n)

	wantBytes := []byte{0x0D, 0x0C, 0x0B, 0x0A}
	got := msg[oSpID : oSpID+4]
	if !bytes.Equal(got, wantBytes) {
		t.Errorf("spID bytes (empty ct): got %x, want %x", got, wantBytes)
	}
}

func TestBuildPwdUpdateSigMsg_SpID_Zero(t *testing.T) {
	nonce := make([]byte, crypto.LenCtBlobNonce)
	tag := make([]byte, crypto.LenCtBlobTag)
	ki := make([]byte, crypto.LenScalarKi)
	msg := crypto.BuildPwdUpdateSigMsg(nonce, nil, tag, ki, 0, 0)

	oSpID := crypto.LenCtBlobNonce + crypto.LenCtBlobTag + crypto.LenScalarKi + 8
	got := msg[oSpID : oSpID+4]
	want := make([]byte, 4) // all zeros for spID=0
	if !bytes.Equal(got, want) {
		t.Errorf("spID=0: got %x, want %x", got, want)
	}
}

// ---------------------------------------------------------------------------
// full-message golden vector
// ---------------------------------------------------------------------------

// TestBuildPwdUpdateSigMsg_GoldenVector validates the entire message byte-by-byte
// against a hand-computed expected value. This pins the wire format completely.
//
// Inputs (all-fixed, no ct):
//   cidNonce  = 0x01 * 24
//   cidCt     = [] (empty)
//   cidTag    = 0x03 * 16
//   kINew     = 0x04 * 32
//   tsU64LE   = 1  (→ 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00)
//   spIDU32LE = 2  (→ 0x02 0x00 0x00 0x00)
func TestBuildPwdUpdateSigMsg_GoldenVector(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, crypto.LenCtBlobNonce)
	tag := bytes.Repeat([]byte{0x03}, crypto.LenCtBlobTag)
	ki := bytes.Repeat([]byte{0x04}, crypto.LenScalarKi)
	msg := crypto.BuildPwdUpdateSigMsg(nonce, []byte{}, tag, ki, 1, 2)

	// Build expected manually.
	var want []byte
	want = append(want, bytes.Repeat([]byte{0x01}, 24)...) // cidNonce
	// cidCt empty
	want = append(want, bytes.Repeat([]byte{0x03}, 16)...) // cidTag
	want = append(want, bytes.Repeat([]byte{0x04}, 32)...) // kINew
	tsWant := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsWant, 1)
	want = append(want, tsWant...) // ts = 1 LE
	spWant := make([]byte, 4)
	binary.LittleEndian.PutUint32(spWant, 2)
	want = append(want, spWant...) // spID = 2 LE

	if !bytes.Equal(msg, want) {
		t.Errorf("golden vector mismatch:\ngot  %x\nwant %x", msg, want)
	}
}

// ---------------------------------------------------------------------------
// no aliasing / mutation
// ---------------------------------------------------------------------------

// TestBuildPwdUpdateSigMsg_NoAlias confirms that mutating an input slice after
// calling BuildPwdUpdateSigMsg does not change the returned message.
func TestBuildPwdUpdateSigMsg_NoAlias(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAA}, crypto.LenCtBlobNonce)
	ct := []byte{0xBB, 0xCC}
	tag := bytes.Repeat([]byte{0xDD}, crypto.LenCtBlobTag)
	ki := bytes.Repeat([]byte{0xEE}, crypto.LenScalarKi)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, 999, 888)
	snapshot := make([]byte, len(msg))
	copy(snapshot, msg)

	// Mutate all inputs.
	for i := range nonce { nonce[i] = 0x00 }
	for i := range ct    { ct[i] = 0x00 }
	for i := range tag   { tag[i] = 0x00 }
	for i := range ki    { ki[i] = 0x00 }

	if !bytes.Equal(msg, snapshot) {
		t.Error("BuildPwdUpdateSigMsg output was mutated after input slices changed (aliasing bug)")
	}
}
