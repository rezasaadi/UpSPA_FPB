package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// contextKey is a dedicated type for values stored in the request context.
type contextKey string
const requestIDKey contextKey = "requestID"

// RequestIDMiddleware assigns a unique ID to every incoming request.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate a random 16-byte identifier.
		bytes := make([]byte, 16)
		rand.Read(bytes)
		reqID := hex.EncodeToString(bytes)

		// Store the ID in the request context and expose it in the response header.
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)

		// Pass the request to the next handler.
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the final response status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// LoggingMiddleware writes structured request logs without exposing secrets.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now() // Start the request timer.

		// Read the request ID that was attached earlier in the middleware chain.
		reqID, _ := r.Context().Value(requestIDKey).(string)

		// Wrap the writer so the final status code can be observed.
		recorder := &statusRecorder{ResponseWriter: w, status: 200}

		// Execute the next handler.
		next.ServeHTTP(recorder, r)

		// Compute request duration after the handler completes.
		duration := time.Since(start)

		// Never log request bodies or secret material here.
		// Use structured logging via slog.
		slog.Info("HTTP Request",
			"id", reqID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration", duration.String(),
		)
	})
}

// RecoverMiddleware converts panics into a safe internal server error response.
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Run this deferred function if the handler panics.
		defer func() {
			if err := recover(); err != nil { // Capture any panic raised by downstream handlers.
				reqID, _ := r.Context().Value(requestIDKey).(string)
				slog.Error("PANIC RECOVERED", "id", reqID, "error", err)
				
				// Return a standard internal error response instead of crashing the server.
				WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Unexpected server error", nil)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
