package api

import (
	"encoding/base64"
	"net/http"

	"upspa/internal/model")

// EvalToprf handles POST /v1/toprf/eval
func (h *Handler) EvalToprf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	var req model.ToprfEvalRequest
	if err := ReadJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "Bad Request: Invalid JSON body", nil)
		return
	}

	// Validate formats and extract fixed lengths
	if err := validateBase64URLNoPad(req.UIDB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_uid", "Bad Request: Invalid uid format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.BlindedB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_blinded", "Bad Request: Invalid blinded point format", nil)
		return
	}

	// Fetch the k_i for this user from the Store
	kIB64, err := h.store.GetKi(r.Context(), req.UIDB64)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "User not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	// (Mock) Cryptographic Evaluation
	_ = kIB64 // mock usage
	
	// Create a dummy 32-byte point for tests
	yB64 := base64.RawURLEncoding.EncodeToString([]byte("mock_y_val_must_be_32_bytes_long"))

	resp := model.ToprfEvalResponse{
		SpID: 1, // Will be injected or fetched from config later
		YB64: yB64,
	}

	WriteJSON(w, http.StatusOK, resp)
}
