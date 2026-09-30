package adminapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Message) }

type Client struct {
	BaseURL string
	Key     ed25519.PrivateKey
	HTTP    *http.Client
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	SignRequest(req, body, c.Key, time.Now())

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// WhoAmI returns the operator email the server maps the signing key to.
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	var out struct {
		Operator string `json:"operator"`
	}
	return out.Operator, c.do(ctx, "GET", "/v1/admin/whoami", nil, &out)
}

func (c *Client) ListIssuers(ctx context.Context) ([]Issuer, error) {
	var out ListIssuersResponse
	return out.Issuers, c.do(ctx, "GET", "/v1/admin/issuers", nil, &out)
}

func (c *Client) GetIssuer(ctx context.Context, id string) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "GET", "/v1/admin/issuers/"+url.PathEscape(id), nil, &out)
}

func (c *Client) CreateIssuer(ctx context.Context, req CreateIssuerRequest) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "POST", "/v1/admin/issuers", req, &out)
}

func (c *Client) UpdateIssuer(ctx context.Context, id string, req UpdateIssuerRequest) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "PATCH", "/v1/admin/issuers/"+url.PathEscape(id), req, &out)
}

func (c *Client) RetireIssuer(ctx context.Context, id string, req RetireRequest) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "POST", "/v1/admin/issuers/"+url.PathEscape(id)+"/retire", req, &out)
}

func (c *Client) CancelRetirement(ctx context.Context, id string) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "DELETE", "/v1/admin/issuers/"+url.PathEscape(id)+"/retire", nil, &out)
}

func (c *Client) PostponeRetirement(ctx context.Context, id string, req PostponeRequest) (*Issuer, error) {
	var out Issuer
	return &out, c.do(ctx, "POST", "/v1/admin/issuers/"+url.PathEscape(id)+"/retire/postpone", req, &out)
}

func (c *Client) ListAudit(ctx context.Context, issuerID string, limit int) ([]AuditEntry, error) {
	q := url.Values{}
	if issuerID != "" {
		q.Set("issuer_id", issuerID)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/admin/audit"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out AuditResponse
	return out.Entries, c.do(ctx, "GET", path, nil, &out)
}
