package server

import (
	"net/http"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
)

// Management API request/response types

// IssuerDetailResponse is the detailed response for a single issuer including keys
// All timestamp strings are in UTC and formatted as RFC3339.
type IssuerDetailResponse struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Cohort    int16               `json:"cohort"`
	MaxTokens int                 `json:"max_tokens"`
	Version   int                 `json:"version"`
	ExpiresAt *string             `json:"expires_at,omitempty"` // RFC3339 UTC timestamp
	CreatedAt *string             `json:"created_at,omitempty"` // RFC3339 UTC timestamp
	ValidFrom *string             `json:"valid_from,omitempty"` // RFC3339 UTC timestamp
	Buffer    int                 `json:"buffer,omitempty"`
	Overlap   int                 `json:"overlap,omitempty"`
	Duration  *string             `json:"duration,omitempty"`
	Keys      []IssuerKeyResponse `json:"keys,omitempty"`
}

// IssuerKeyResponse represents an issuer key in the API response
// All timestamp strings are in UTC and formatted as RFC3339.
type IssuerKeyResponse struct {
	ID        string  `json:"id,omitempty"`
	PublicKey string  `json:"public_key"`
	Cohort    int16   `json:"cohort"`
	StartAt   *string `json:"start_at,omitempty"`   // RFC3339 UTC timestamp
	EndAt     *string `json:"end_at,omitempty"`     // RFC3339 UTC timestamp
	CreatedAt *string `json:"created_at,omitempty"` // RFC3339 UTC timestamp
}

// IssuerListResponse is the response for listing issuers
type IssuerListResponse struct {
	Issuers []IssuerDetailResponse `json:"issuers"`
	Total   int                    `json:"total"`
}

// manageListIssuersHandler handles GET /api/v1/manage/issuers
func (c *Server) manageListIssuersHandler(w http.ResponseWriter, r *http.Request) *AppError {
	manageIssuerCallTotal.WithLabelValues("list").Inc()

	// Verify request signature
	if _, appErr := c.verifyManagementRequest(r); appErr != nil {
		return appErr
	}

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
