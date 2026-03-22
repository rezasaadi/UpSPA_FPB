package api

import (
	"net/http"
)

// NewRouter is the central HTTP router for the service.
func NewRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()

	// System health
	mux.HandleFunc("GET /v1/health", handleHealth)

	// Setup
	mux.HandleFunc("POST /v1/setup", h.Setup)
	mux.HandleFunc("GET /v1/setup/{uid_b64}", h.SetupGet)

	// Cryptographic evaluation
	mux.HandleFunc("POST /v1/toprf/eval", h.EvalToprf)

	// Record management
	mux.HandleFunc("POST /v1/records", h.RecordCreate)
	mux.HandleFunc("GET /v1/records/{suid_b64}", h.RecordGet)
	mux.HandleFunc("PUT /v1/records/{suid_b64}", h.RecordUpdate)
	mux.HandleFunc("DELETE /v1/records/{suid_b64}", h.RecordDelete)

	// Password update
	mux.HandleFunc("POST /v1/password-update", h.PasswordUpdate)

	// Wrap the router with middleware.
	handler := RequestIDMiddleware(LoggingMiddleware(RecoverMiddleware(mux)))

	return handler
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}