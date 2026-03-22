package model

// CtBlob is the encrypted payload container used for both cid and cj.
type CtBlob struct {
	Nonce string `json:"nonce"`
	Ct    string `json:"ct"`
	Tag   string `json:"tag"`
}

// ----------------------------------------------------
// Π1: SETUP models
// ----------------------------------------------------

// POST /v1/setup request
type SetupRequest struct {
	UIDB64   string `json:"uid_b64"`
	SigPkB64 string `json:"sig_pk_b64"`
	CID      CtBlob `json:"cid"`
	KIB64    string `json:"k_i_b64"`
}

// GET /v1/setup/{uid_b64} response
type SetupResponse struct {
	UIDB64   string `json:"uid_b64"`
	SigPkB64 string `json:"sig_pk_b64"`
	CID      CtBlob `json:"cid"`
}

// ----------------------------------------------------
// Π2: TOPRF models
// ----------------------------------------------------

// POST /v1/toprf/eval request
type ToprfEvalRequest struct {
	UIDB64     string `json:"uid_b64"`
	BlindedB64 string `json:"blinded_b64"`
}

// POST /v1/toprf/eval response
type ToprfEvalResponse struct {
	SpID uint32 `json:"sp_id"`
	YB64 string `json:"y_b64"`
}

// ----------------------------------------------------
// Π3 and Π4: RECORDS models
// ----------------------------------------------------

// POST /v1/records create request
type RecordCreateRequest struct {
	SUIDB64 string `json:"suid_b64"`
	CJ      CtBlob `json:"cj"`
}

// PUT /v1/records/{suid_b64} update request
type RecordUpdateRequest struct {
	CJ CtBlob `json:"cj"`
}

// GET /v1/records/{suid_b64} response
type RecordResponse struct {
	SUIDB64 string `json:"suid_b64"`
	CJ      CtBlob `json:"cj"`
}

// ----------------------------------------------------
// Π5: PASSWORD UPDATE models
// ----------------------------------------------------

// POST /v1/password-update request
type PasswordUpdateRequest struct {
	UIDB64    string `json:"uid_b64"`
	SpID      uint32 `json:"sp_id"`
	Timestamp uint64 `json:"timestamp"`
	SigB64    string `json:"sig_b64"`
	CIDNew    CtBlob `json:"cid_new"`
	KINewB64  string `json:"k_i_new_b64"`
}

// ----------------------------------------------------
// ERROR standard error schema
// ----------------------------------------------------

// ErrorDetail is the error payload designed in week 1.
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"` // Omit from JSON when empty.
}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}