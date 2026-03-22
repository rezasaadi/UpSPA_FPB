package api

import (
	"net/http"
	"upspa/internal/model"
)

// RecordCreate handles POST /v1/records
func (h *Handler) RecordCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	var req model.RecordCreateRequest
	if err := ReadJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "Bad Request: Invalid JSON body", nil)
		return
	}

	// Validate field lengths
	if err := validateBase64URLNoPad(req.SUIDB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_suid", "Bad Request: Invalid suid format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CJ.Nonce, 24); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_nonce", "Bad Request: Invalid cj_nonce format or length", nil)
		return
	}
	// CIPHERSP_PT_LEN is 40 bytes
	if err := validateBase64URLNoPad(req.CJ.Ct, 40); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_ct", "Bad Request: Invalid cj_ct format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CJ.Tag, 16); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_tag", "Bad Request: Invalid cj_tag format or length", nil)
		return
	}

	created, err := h.store.PutRecord(r.Context(), req.SUIDB64, req.CJ.Nonce, req.CJ.Ct, req.CJ.Tag)
	if err != nil {
		if err == ErrConflict {
			WriteError(w, http.StatusConflict, "conflict", "Record already exists", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	if !created {
		WriteError(w, http.StatusConflict, "conflict", "Record already exists", nil)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// RecordGet handles GET /v1/records/{suid_b64}
func (h *Handler) RecordGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	suidB64 := r.PathValue("suid_b64")
	if err := validateBase64URLNoPad(suidB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_suid", "Bad Request: Invalid suid format or length", nil)
		return
	}

	resp, err := h.store.GetRecord(r.Context(), suidB64)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "Record not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	WriteJSON(w, http.StatusOK, resp)
}

// RecordUpdate handles PUT /v1/records/{suid_b64}
func (h *Handler) RecordUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	suidB64 := r.PathValue("suid_b64")
	if err := validateBase64URLNoPad(suidB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_suid", "Bad Request: Invalid suid format or length", nil)
		return
	}

	var req model.RecordUpdateRequest
	if err := ReadJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "Bad Request: Invalid JSON body", nil)
		return
	}

	if err := validateBase64URLNoPad(req.CJ.Nonce, 24); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_nonce", "Bad Request: Invalid cj_nonce format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CJ.Ct, 40); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_ct", "Bad Request: Invalid cj_ct format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CJ.Tag, 16); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cj_tag", "Bad Request: Invalid cj_tag format or length", nil)
		return
	}

	err := h.store.UpdateRecord(r.Context(), suidB64, req.CJ.Nonce, req.CJ.Ct, req.CJ.Tag)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "Record not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RecordDelete handles DELETE /v1/records/{suid_b64}
func (h *Handler) RecordDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	suidB64 := r.PathValue("suid_b64")
	if err := validateBase64URLNoPad(suidB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_suid", "Bad Request: Invalid suid format or length", nil)
		return
	}

	err := h.store.DeleteRecord(r.Context(), suidB64)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "Record not found", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}