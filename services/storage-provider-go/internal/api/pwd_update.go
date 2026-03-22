package api

import (
	"encoding/base64"
	"net/http"
	"upspa/internal/model"
)

// PasswordUpdate handles POST /v1/password-update
func (h *Handler) PasswordUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	var req model.PasswordUpdateRequest
	if err := ReadJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "Bad Request: Invalid JSON body", nil)
		return
	}

	// Validate fixed lengths
	if err := validateBase64URLNoPad(req.UIDB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_uid", "Bad Request: Invalid uid format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.SigB64, 64); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_sig", "Bad Request: Invalid sig format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CIDNew.Nonce, 24); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_nonce", "Bad Request: Invalid cid_nonce format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CIDNew.Ct, 96); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_ct", "Bad Request: Invalid cid_ct format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CIDNew.Tag, 16); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_tag", "Bad Request: Invalid cid_tag format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.KINewB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_ki_new", "Bad Request: Invalid k_i_new format or length", nil)
		return
	}

	// Lookup existing setup state to get the verification key and last timestamp
	sigPkB64, lastTimestamp, err := h.store.GetPasswordUpdateState(r.Context(), req.UIDB64)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "User not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	// Replay Protection
	if req.Timestamp <= lastTimestamp {
		WriteError(w, http.StatusConflict, "stale_timestamp", "Timestamp must be strictly greater than last update", nil)
		return
	}

	// Ed25519 Signature Verification
	sigPkBytes, _ := base64.RawURLEncoding.DecodeString(sigPkB64)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(req.SigB64)
	
	// Create mock msg for now. In real integration, we'd rebuild exactly per protocol-phases.md
	msgBytes := []byte("mock_signature_message_payload")
	
	if !h.crypto.VerifyEd25519(sigPkBytes, msgBytes, sigBytes) {
		WriteError(w, http.StatusUnauthorized, "invalid_signature", "Ed25519 signature is invalid", nil)
		return
	}

	// Save the new state
	err = h.store.PutPasswordUpdate(r.Context(), req.UIDB64, req.CIDNew.Nonce, req.CIDNew.Ct, req.CIDNew.Tag, req.KINewB64, req.Timestamp)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}