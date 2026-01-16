package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Management API request/response types

// IssuerDetailResponse is the detailed response for a single issuer including keys
type IssuerDetailResponse struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Cohort    int16               `json:"cohort"`
	MaxTokens int                 `json:"max_tokens"`
	Version   int                 `json:"version"`
	ExpiresAt *string             `json:"expires_at,omitempty"`
	CreatedAt *string             `json:"created_at,omitempty"`
	ValidFrom *string             `json:"valid_from,omitempty"`
	Buffer    int                 `json:"buffer,omitempty"`
	Overlap   int                 `json:"overlap,omitempty"`
	Duration  *string             `json:"duration,omitempty"`
	Keys      []IssuerKeyResponse `json:"keys,omitempty"`
}

// IssuerKeyResponse represents an issuer key in the API response
type IssuerKeyResponse struct {
	ID        string  `json:"id,omitempty"`
	PublicKey string  `json:"public_key"`
	Cohort    int16   `json:"cohort"`
	StartAt   *string `json:"start_at,omitempty"`
	EndAt     *string `json:"end_at,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
}

// IssuerListResponse is the response for listing issuers
type IssuerListResponse struct {
	Issuers []IssuerDetailResponse `json:"issuers"`
	Total   int                    `json:"total"`
}

// CreateIssuerRequest is the request body for creating an issuer
type CreateIssuerRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	Version   int        `json:"version"` // 1, 2, or 3
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ValidFrom *time.Time `json:"valid_from,omitempty"`
	Duration  string     `json:"duration,omitempty"` // ISO 8601 duration for v3
	Buffer    int        `json:"buffer,omitempty"`   // for v3
	Overlap   int        `json:"overlap,omitempty"`  // for v3
}

// manageListIssuersHandler handles GET /api/v1/manage/issuers
func (c *Server) manageListIssuersHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("list").Inc()

	issuers, err := c.FetchAllIssuers()
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to fetch issuers",
			Code:    http.StatusInternalServerError,
		}
	}

	response := IssuerListResponse{
		Issuers: make([]IssuerDetailResponse, len(issuers)),
		Total:   len(issuers),
	}

	for i, issuer := range issuers {
		response.Issuers[i] = makeIssuerDetailResponse(&issuer)
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

// manageGetIssuerHandler handles GET /api/v1/manage/issuers/{id}
func (c *Server) manageGetIssuerHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("get").Inc()

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

	response := makeIssuerDetailResponse(issuer)
	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// manageCreateIssuerHandler handles POST /api/v1/manage/issuers
func (c *Server) manageCreateIssuerHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("create").Inc()

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req CreateIssuerRequest
	if err := decoder.Decode(&req); err != nil {
		return WrapError(err, "Could not parse request body", http.StatusBadRequest)
	}

	// Validate required fields
	if req.Name == "" {
		return &AppError{
			Message: "Name is required",
			Code:    http.StatusBadRequest,
		}
	}

	// Default version to 3 if not specified
	if req.Version == 0 {
		req.Version = 3
	}

	if req.Version < 1 || req.Version > 3 {
		return &AppError{
			Message: "Version must be 1, 2, or 3",
			Code:    http.StatusBadRequest,
		}
	}

	// Validate expiration
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		return &AppError{
			Message: "Expiration time has passed",
			Code:    http.StatusBadRequest,
		}
	}

	// V3 specific validation
	if req.Version == 3 {
		if req.Buffer <= 0 {
			return &AppError{
				Message: "Buffer is required for v3 issuers and must be greater than 0",
				Code:    http.StatusBadRequest,
			}
		}
		if req.Duration == "" {
			return &AppError{
				Message: "Duration is required for v3 issuers",
				Code:    http.StatusBadRequest,
			}
		}
	}

	// Default max tokens
	if req.MaxTokens == 0 {
		req.MaxTokens = 40
	}

	// Build issuer model
	issuer := model.Issuer{
		IssuerType:   req.Name,
		IssuerCohort: req.Cohort,
		MaxTokens:    req.MaxTokens,
		Version:      req.Version,
		Buffer:       req.Buffer,
		Overlap:      req.Overlap,
		Duration:     &req.Duration,
		ValidFrom:    req.ValidFrom,
	}

	if req.ExpiresAt != nil {
		issuer.ExpiresAt = pq.NullTime{Time: *req.ExpiresAt, Valid: true}
	}

	// Create the issuer
	if err := c.createV3Issuer(issuer); err != nil {
		// Check for duplicate
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return &AppError{
				Cause:   err,
				Message: "Issuer with this name and cohort already exists",
				Code:    http.StatusConflict,
			}
		}
		return &AppError{
			Cause:   err,
			Message: "Failed to create issuer",
			Code:    http.StatusInternalServerError,
		}
	}

	w.WriteHeader(http.StatusCreated)
	return nil
}

// manageDeleteIssuerHandler handles DELETE /api/v1/manage/issuers/{id}
func (c *Server) manageDeleteIssuerHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("delete").Inc()

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

	// Delete the issuer
	deleted, err := c.deleteIssuerByID(issuerID)
	if err != nil {
		return &AppError{
			Cause:   err,
			Message: "Failed to delete issuer",
			Code:    http.StatusInternalServerError,
		}
	}

	if !deleted {
		return &AppError{
			Message: "Issuer not found",
			Code:    http.StatusNotFound,
		}
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// makeIssuerDetailResponse converts an issuer model to a detailed response
func makeIssuerDetailResponse(issuer *model.Issuer) IssuerDetailResponse {
	resp := IssuerDetailResponse{
		ID:        issuer.ID.String(),
		Name:      issuer.IssuerType,
		Cohort:    issuer.IssuerCohort,
		MaxTokens: issuer.MaxTokens,
		Version:   issuer.Version,
		Buffer:    issuer.Buffer,
		Overlap:   issuer.Overlap,
		Duration:  issuer.Duration,
	}

	if issuer.ExpiresAt.Valid && !issuer.ExpiresAt.Time.IsZero() {
		expiresAt := issuer.ExpiresAt.Time.Format(time.RFC3339)
		resp.ExpiresAt = &expiresAt
	}

	if issuer.CreatedAt.Valid && !issuer.CreatedAt.Time.IsZero() {
		createdAt := issuer.CreatedAt.Time.Format(time.RFC3339)
		resp.CreatedAt = &createdAt
	}

	if issuer.ValidFrom != nil && !issuer.ValidFrom.IsZero() {
		validFrom := issuer.ValidFrom.Format(time.RFC3339)
		resp.ValidFrom = &validFrom
	}

	// Convert keys
	resp.Keys = make([]IssuerKeyResponse, len(issuer.Keys))
	for i, key := range issuer.Keys {
		keyResp := IssuerKeyResponse{
			Cohort: key.Cohort,
		}

		if key.ID != nil {
			keyResp.ID = key.ID.String()
		}

		if key.PublicKey != nil {
			keyResp.PublicKey = *key.PublicKey
		}

		if key.StartAt != nil && !key.StartAt.IsZero() {
			startAt := key.StartAt.Format(time.RFC3339)
			keyResp.StartAt = &startAt
		}

		if key.EndAt != nil && !key.EndAt.IsZero() {
			endAt := key.EndAt.Format(time.RFC3339)
			keyResp.EndAt = &endAt
		}

		if key.CreatedAt != nil && !key.CreatedAt.IsZero() {
			createdAt := key.CreatedAt.Format(time.RFC3339)
			keyResp.CreatedAt = &createdAt
		}

		resp.Keys[i] = keyResp
	}

	return resp
}
