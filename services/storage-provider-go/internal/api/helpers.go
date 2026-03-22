package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	// Update this import if the module path changes.
	// It currently matches the module name declared in go.mod.
	"upspa/internal/model" 
)

// maxBodyBytes is the maximum allowed request body size, set to 8 KB.
const maxBodyBytes = 8 * 1024 

// WriteJSON serializes a Go value to JSON and writes it to the response.
func WriteJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Return early when there is no payload.
	if data == nil {
		return nil
	}

	return json.NewEncoder(w).Encode(data)
}

// WriteError writes the standard JSON error response defined for the API.
func WriteError(w http.ResponseWriter, status int, code string, message string, details map[string]any) {
	errResp := model.ErrorResponse{
		Error: model.ErrorDetail{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
	WriteJSON(w, status, errResp)
}

// ReadJSON reads a request body into dst with content-type and size validation.
func ReadJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	// 1. Security check: verify that the incoming payload is JSON.
	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errors.New("Content-Type must be application/json")
		}
	}

	// 2. Security check: prevent oversized bodies from exhausting server resources.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	// 3. Decode the request body into the destination value.
	dec := json.NewDecoder(r.Body)
	
	// Reject unknown extra fields for stricter input validation.
	dec.DisallowUnknownFields()

	err := dec.Decode(dst)
	if err != nil {
		return err
	}

	// Ensure the body contains exactly one JSON object and nothing else.
	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return errors.New("body must only contain a single JSON object")
	}

	return nil
}