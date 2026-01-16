package server

import (
	"encoding/json"
	"net/http"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Key Management API request/response types

// KeyListResponse is the response for listing keys
type KeyListResponse struct {
	Keys  []IssuerKeyResponse `json:"keys"`
	Total int                 `json:"total"`
}

// CreateKeyRequest is the request body for creating a key
type CreateKeyRequest struct {
	StartAt *time.Time `json:"start_at,omitempty"`
	EndAt   *time.Time `json:"end_at,omitempty"`
}

// RotateKeysRequest is the request body for rotating keys
type RotateKeysRequest struct {
	Count int `json:"count,omitempty"` // Number of new keys to create (default: 1)
}

// RotateKeysResponse is the response for key rotation
type RotateKeysResponse struct {
	CreatedKeys []IssuerKeyResponse `json:"created_keys"`
	Message     string              `json:"message"`
}

// manageListKeysHandler handles GET /api/v1/manage/issuers/{id}/keys
func (c *Server) manageListKeysHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("list_keys").Inc()

	issuerID := chi.URLParam(r, "id")
	if issuerID == "" {
		return &AppError{
			Message: "Issuer ID is required",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate UUID format
	if _, err := uuid.Parse(issuerID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid issuer ID format",
			Code:    http.StatusBadRequest,
		}
	}

	// Check if we should include all keys (including expired)
	includeExpired := r.URL.Query().Get("include_expired") == "true"

	keys, err := c.fetchAllIssuerKeys(issuerID, includeExpired)
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to fetch keys",
			Code:    http.StatusInternalServerError,
		}
	}

	response := KeyListResponse{
		Keys:  make([]IssuerKeyResponse, len(keys)),
		Total: len(keys),
	}

	for i, key := range keys {
		response.Keys[i] = makeKeyResponse(&key)
	}

	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// manageGetKeyHandler handles GET /api/v1/manage/issuers/{id}/keys/{keyId}
func (c *Server) manageGetKeyHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("get_key").Inc()

	issuerID := chi.URLParam(r, "id")
	keyID := chi.URLParam(r, "keyId")

	if issuerID == "" || keyID == "" {
		return &AppError{
			Message: "Issuer ID and Key ID are required",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate UUID formats
	if _, err := uuid.Parse(issuerID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid issuer ID format",
			Code:    http.StatusBadRequest,
		}
	}
	if _, err := uuid.Parse(keyID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid key ID format",
			Code:    http.StatusBadRequest,
		}
	}

	key, err := c.fetchKeyByID(issuerID, keyID)
	if err != nil {
		if err == errKeyNotFound {
			return &AppError{
				Message: "Key not found",
				Code:    http.StatusNotFound,
			}
		}
		return &AppError{
			Cause:   err,
			Message: "Failed to fetch key",
			Code:    http.StatusInternalServerError,
		}
	}

	response := makeKeyResponse(key)
	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// manageCreateKeyHandler handles POST /api/v1/manage/issuers/{id}/keys
func (c *Server) manageCreateKeyHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("create_key").Inc()

	issuerID := chi.URLParam(r, "id")
	if issuerID == "" {
		return &AppError{
			Message: "Issuer ID is required",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate UUID format
	if _, err := uuid.Parse(issuerID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid issuer ID format",
			Code:    http.StatusBadRequest,
		}
	}

	// Fetch the issuer to get cohort and validate it exists
	issuer, err := c.fetchIssuerByID(issuerID)
	if err != nil {
		if err == errIssuerNotFound {
			return &AppError{
				Message: "Issuer not found",
				Code:    http.StatusNotFound,
			}
		}
		return &AppError{
			Cause:   err,
			Message: "Failed to fetch issuer",
			Code:    http.StatusInternalServerError,
		}
	}

	// Parse request body
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req CreateKeyRequest
	if err := decoder.Decode(&req); err != nil {
		// Empty body is OK, we'll use defaults
		req = CreateKeyRequest{}
	}

	// Generate a new signing key
	signingKey, err := crypto.RandomSigningKey()
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to generate signing key",
			Code:    http.StatusInternalServerError,
		}
	}

	signingKeyTxt, err := signingKey.MarshalText()
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to marshal signing key",
			Code:    http.StatusInternalServerError,
		}
	}

	pubKeyTxt, err := signingKey.PublicKey().MarshalText()
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to marshal public key",
			Code:    http.StatusInternalServerError,
		}
	}

	// Create the key
	key := model.IssuerKeys{
		SigningKey: signingKeyTxt,
		PublicKey:  ptr.FromString(string(pubKeyTxt)),
		Cohort:     issuer.IssuerCohort,
		IssuerID:   issuer.ID,
		StartAt:    req.StartAt,
		EndAt:      req.EndAt,
	}

	createdKey, err := c.createIssuerKey(issuerID, &key)
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to create key",
			Code:    http.StatusInternalServerError,
		}
	}

	// Invalidate cache
	c.invalidateIssuerCaches()

	response := makeKeyResponse(createdKey)
	if err := RenderContent(response, w, http.StatusCreated); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// manageDeleteKeyHandler handles DELETE /api/v1/manage/issuers/{id}/keys/{keyId}
func (c *Server) manageDeleteKeyHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("delete_key").Inc()

	issuerID := chi.URLParam(r, "id")
	keyID := chi.URLParam(r, "keyId")

	if issuerID == "" || keyID == "" {
		return &AppError{
			Message: "Issuer ID and Key ID are required",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate UUID formats
	if _, err := uuid.Parse(issuerID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid issuer ID format",
			Code:    http.StatusBadRequest,
		}
	}
	if _, err := uuid.Parse(keyID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid key ID format",
			Code:    http.StatusBadRequest,
		}
	}

	deleted, err := c.deleteKeyByID(issuerID, keyID)
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to delete key",
			Code:    http.StatusInternalServerError,
		}
	}

	if !deleted {
		return &AppError{
			Message: "Key not found",
			Code:    http.StatusNotFound,
		}
	}

	// Invalidate cache
	c.invalidateIssuerCaches()

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// manageRotateKeysHandler handles POST /api/v1/manage/issuers/{id}/keys/rotate
func (c *Server) manageRotateKeysHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("rotate_keys").Inc()

	issuerID := chi.URLParam(r, "id")
	if issuerID == "" {
		return &AppError{
			Message: "Issuer ID is required",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate UUID format
	if _, err := uuid.Parse(issuerID); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Invalid issuer ID format",
			Code:    http.StatusBadRequest,
		}
	}

	// Fetch the issuer
	issuer, err := c.fetchIssuerByID(issuerID)
	if err != nil {
		if err == errIssuerNotFound {
			return &AppError{
				Message: "Issuer not found",
				Code:    http.StatusNotFound,
			}
		}
		return &AppError{
			Cause:   err,
			Message: "Failed to fetch issuer",
			Code:    http.StatusInternalServerError,
		}
	}

	// Parse request body
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req RotateKeysRequest
	if err := decoder.Decode(&req); err != nil {
		req = RotateKeysRequest{}
	}

	if req.Count <= 0 {
		req.Count = 1
	}

	// Create new keys
	createdKeys, err := c.rotateIssuerKeys(issuer, req.Count)
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to rotate keys",
			Code:    http.StatusInternalServerError,
		}
	}

	// Invalidate cache
	c.invalidateIssuerCaches()

	response := RotateKeysResponse{
		CreatedKeys: make([]IssuerKeyResponse, len(createdKeys)),
		Message:     "Keys rotated successfully",
	}

	for i, key := range createdKeys {
		response.CreatedKeys[i] = makeKeyResponse(&key)
	}

	if err := RenderContent(response, w, http.StatusCreated); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// makeKeyResponse converts a key model to a response
func makeKeyResponse(key *model.IssuerKeys) IssuerKeyResponse {
	resp := IssuerKeyResponse{
		Cohort: key.Cohort,
	}

	if key.ID != nil {
		resp.ID = key.ID.String()
	}

	if key.PublicKey != nil {
		resp.PublicKey = *key.PublicKey
	}

	if key.StartAt != nil && !key.StartAt.IsZero() {
		startAt := key.StartAt.Format(time.RFC3339)
		resp.StartAt = &startAt
	}

	if key.EndAt != nil && !key.EndAt.IsZero() {
		endAt := key.EndAt.Format(time.RFC3339)
		resp.EndAt = &endAt
	}

	if key.CreatedAt != nil && !key.CreatedAt.IsZero() {
		createdAt := key.CreatedAt.Format(time.RFC3339)
		resp.CreatedAt = &createdAt
	}

	return resp
}

// invalidateIssuerCaches invalidates all issuer-related caches
func (c *Server) invalidateIssuerCaches() {
	if c.caches != nil {
		c.caches.Issuers.Delete("all")
		// Note: Individual issuer and cohort caches will expire naturally
		// or could be cleared more aggressively if needed
	}
}
