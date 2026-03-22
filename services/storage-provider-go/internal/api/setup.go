package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"upspa/internal/model"
)

var (
	ErrInvalidBase64 = errors.New("invalid base64url encoding")
	ErrInvalidLength = errors.New("invalid decoded byte length")
	
	// Database standard errors
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record conflict")
)

// Store defines database operations for the handlers.
// This interface allows us to use a fake database for testing.
type Store interface {
	// Setup (Pi1)
	PutSetup(ctx context.Context, uid, sigPk, cidNonce, cidCt, cidTag, kI string) (bool, error)
	GetSetup(ctx context.Context, uid string) (*model.SetupResponse, error)

	// TOPRF Eval (Pi2)
	GetKi(ctx context.Context, uid string) (string, error)

	// Records (Pi3, Pi4)
	PutRecord(ctx context.Context, suid string, cjNonce, cjCt, cjTag string) (bool, error)
	GetRecord(ctx context.Context, suid string) (*model.RecordResponse, error)
	UpdateRecord(ctx context.Context, suid string, cjNonce, cjCt, cjTag string) error
	DeleteRecord(ctx context.Context, suid string) error

	// Password Update (Pi5)
	GetPasswordUpdateState(ctx context.Context, uid string) (sigPk string, lastTimestamp uint64, err error)
	PutPasswordUpdate(ctx context.Context, uid string, newCidNonce, newCidCt, newCidTag, newKi string, newTimestamp uint64) error
}

// CryptoHelper defines crypto operations for the handlers.
type CryptoHelper interface {
	VerifyEd25519(sigPk []byte, msg []byte, sig []byte) bool
}

// DefaultCryptoHelper is a basic placeholder for real crypto usage.
type DefaultCryptoHelper struct{}

func (d *DefaultCryptoHelper) VerifyEd25519(sigPk []byte, msg []byte, sig []byte) bool {
	return true
}

// Handler holds the background services needed to run the API.
type Handler struct {
	store  Store
	crypto CryptoHelper
}

// NewHandler creates a new Handler with the given Store.
func NewHandler(s Store) *Handler {
	return &Handler{
		store:  s,
		crypto: &DefaultCryptoHelper{},
	}
}

// Setup handles POST /v1/setup
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", nil)
		return
	}

	var req model.SetupRequest
	if err := ReadJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json_body", "Bad Request: Invalid JSON body", map[string]any{"error": err.Error()})
		return
	}

	// Validate data formats and sizes
	if err := validateBase64URLNoPad(req.UIDB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_uid", "Bad Request: Invalid uid format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.SigPkB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_sig_pk", "Bad Request: Invalid sig_pk format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CID.Nonce, 24); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_nonce", "Bad Request: Invalid cid_nonce format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CID.Ct, 96); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_ct", "Bad Request: Invalid cid_ct format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.CID.Tag, 16); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_cid_tag", "Bad Request: Invalid cid_tag format or length", nil)
		return
	}
	if err := validateBase64URLNoPad(req.KIB64, 32); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_k_i", "Bad Request: Invalid k_i format or length", nil)
		return
	}

	// Save to database
	created, err := h.store.PutSetup(
		r.Context(),
		req.UIDB64,
		req.SigPkB64,
		req.CID.Nonce,
		req.CID.Ct,
		req.CID.Tag,
		req.KIB64,
	)

	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal Server Error", nil)
		return
	}

	// Return OK if already exists
	if !created {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// validateBase64URLNoPad checks if a base64 string matches the expected byte size.
func validateBase64URLNoPad(s string, expectedLen int) error {
	if s == "" {
		return ErrInvalidBase64
	}

	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ErrInvalidBase64
	}

	if len(decoded) != expectedLen {
		return ErrInvalidLength
	}

	return nil
}