package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the Challenge Bypass Server API
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IssuerDetailResponse represents an issuer from the API
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

// IssuerKeyResponse represents an issuer key from the API
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
	Name      string  `json:"name"`
	Cohort    int16   `json:"cohort"`
	MaxTokens int     `json:"max_tokens"`
	Version   int     `json:"version"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	ValidFrom *string `json:"valid_from,omitempty"`
	Duration  string  `json:"duration,omitempty"`
	Buffer    int     `json:"buffer,omitempty"`
	Overlap   int     `json:"overlap,omitempty"`
}

// APIError represents an error response from the API
type APIError struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// handleResponse processes the response and handles errors
func handleResponse(resp *http.Response, result interface{}) error {
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			return &APIError{
				Message:    string(bodyBytes),
				StatusCode: resp.StatusCode,
			}
		}
		apiErr.StatusCode = resp.StatusCode
		return &apiErr
	}

	if result != nil && len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// ListIssuers fetches all issuers
func (c *Client) ListIssuers() (*IssuerListResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/api/v1/manage/issuers", nil)
	if err != nil {
		return nil, err
	}

	var result IssuerListResponse
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetIssuer fetches a single issuer by ID
func (c *Client) GetIssuer(id string) (*IssuerDetailResponse, error) {
	resp, err := c.doRequest(http.MethodGet, "/api/v1/manage/issuers/"+id, nil)
	if err != nil {
		return nil, err
	}

	var result IssuerDetailResponse
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateIssuer creates a new issuer
func (c *Client) CreateIssuer(req *CreateIssuerRequest) error {
	resp, err := c.doRequest(http.MethodPost, "/api/v1/manage/issuers", req)
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}

// DeleteIssuer deletes an issuer by ID
func (c *Client) DeleteIssuer(id string) error {
	resp, err := c.doRequest(http.MethodDelete, "/api/v1/manage/issuers/"+id, nil)
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}
