// SetupGet fetches the stored setup material.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)

package api

import (
	"net/http"
)

// SetupGet handles GET /v1/setup/{uid_b64}
func (h *Handler) SetupGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	// Validate parameter format
	uidB64 := r.PathValue("uid_b64")
	if err := validateBase64URLNoPad(uidB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_uid", "Bad Request: Invalid uid format or length", nil)
		return
	}

	resp, err := h.store.GetSetup(r.Context(), uidB64)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "User setup not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	WriteJSON(w, http.StatusOK, resp)
}