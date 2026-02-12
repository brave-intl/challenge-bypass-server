package server

import (
	"encoding/json"
	"net/http"
	"strings"
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
// All timestamps should be in UTC and are formatted as RFC3339 in JSON.
type CreateKeyRequest struct {
	StartAt *time.Time `json:"start_at,omitempty"` // UTC timestamp
	EndAt   *time.Time `json:"end_at,omitempty"`   // UTC timestamp
}

// RotateKeysRequest is the request body for rotating keys
// All timestamps and durations should be in UTC.
type RotateKeysRequest struct {
	Count   int    `json:"count,omitempty"`   // Number of new keys to create (default: 1)
	Overlap string `json:"overlap,omitempty"` // ISO 8601 duration for overlap period (default: P1M = 1 month)
}

// RotateKeysResponse is the response for key rotation
type RotateKeysResponse struct {
	CreatedKeys []IssuerKeyResponse `json:"created_keys"` // Newly created keys
	UpdatedKeys []IssuerKeyResponse `json:"updated_keys"` // Previously active keys with updated expiration
	Message     string              `json:"message"`
}

// manageListKeysHandler handles GET /api/v1/manage/issuers/{id}/keys
func (c *Server) manageListKeysHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("list_keys").Inc()

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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

	// Check if force delete is requested
	forceDelete := r.URL.Query().Get("force") == "true"

	// Fetch the key to check if it's still active
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

	// Check if key is still active (can be used for signing or redemption)
	if !forceDelete && isKeyActive(key) {
		return &AppError{
			Message: "Cannot delete active key. This key is still valid for signing or redemption. " +
				"To safely retire this key, wait until after its end_at time, or use key rotation to create new keys. " +
				"If you must delete this key immediately, use ?force=true (WARNING: this will invalidate tokens signed with this key).",
			Code: http.StatusConflict,
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

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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

	// Validate maximum key count to prevent resource exhaustion
	if req.Count > 300 {
		return &AppError{
			Message: "Cannot create more than 300 keys in a single rotation",
			Code:    http.StatusBadRequest,
		}
	}

	// Rotate keys (create new keys and update old keys with overlap)
	createdKeys, updatedKeys, err := c.rotateIssuerKeys(issuer, req.Count, req.Overlap)
	if err != nil {
		// Check if this is a validation error (bad input) vs internal error
		errMsg := err.Error()
		statusCode := http.StatusInternalServerError
		message := "Failed to rotate keys"

		// Validation errors should return 400
		if strings.Contains(errMsg, "overlap duration must be") ||
			strings.Contains(errMsg, "failed to parse") ||
			strings.Contains(errMsg, "failed to calculate overlap duration") {
			statusCode = http.StatusBadRequest
			message = errMsg
		}

		return &AppError{
			Cause:   err,
			Message: message,
			Code:    statusCode,
		}
	}

	// Invalidate cache
	c.invalidateIssuerCaches()

	response := RotateKeysResponse{
		CreatedKeys: make([]IssuerKeyResponse, len(createdKeys)),
		UpdatedKeys: make([]IssuerKeyResponse, len(updatedKeys)),
		Message:     "Keys rotated successfully",
	}

	for i, key := range createdKeys {
		response.CreatedKeys[i] = makeKeyResponse(&key)
	}

	for i, key := range updatedKeys {
		response.UpdatedKeys[i] = makeKeyResponse(&key)
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

// isKeyActive returns true if the key is still active (can be used for signing or redemption)
// A key is considered active if:
// - It has no end_at time (never expires), OR
// - Its end_at time is in the future
func isKeyActive(key *model.IssuerKeys) bool {
	if key.EndAt == nil || key.EndAt.IsZero() {
		// No expiration set - key is always active
		return true
	}
	// Key is active if end_at is in the future
	return key.EndAt.After(time.Now().UTC())
}

// countActiveKeys returns the number of active keys
func countActiveKeys(keys []model.IssuerKeys) int {
	count := 0
	for _, key := range keys {
		if isKeyActive(&key) {
			count++
		}
	}
	return count
}
