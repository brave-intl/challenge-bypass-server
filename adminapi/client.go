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
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

const maxResponseSize = 8 << 20

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
	if err := SignRequest(req, c.Key, time.Now()); err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
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

// WhoAmI returns the operator ID the server maps the signing key to.
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	var out WhoAmIResponse
	err := c.do(ctx, "GET", "/v1/admin/whoami", nil, &out)
	return out.Operator, err
}

func (c *Client) ListIssuers(ctx context.Context) ([]Issuer, error) {
	var out []Issuer
	err := c.do(ctx, "GET", "/v1/admin/issuers", nil, &out)
	return out, err
}

// issuer calls an /v1/admin/issuers endpoint that returns one issuer. An
// empty id calls /v1/admin/issuers itself.
func (c *Client) issuer(ctx context.Context, method, id, suffix string, in any) (*Issuer, error) {
	path := "/v1/admin/issuers"
	if id != "" {
		path += "/" + url.PathEscape(id) + suffix
	}
	var out Issuer
	err := c.do(ctx, method, path, in, &out)
	return &out, err
}

func (c *Client) GetIssuer(ctx context.Context, id string) (*Issuer, error) {
	return c.issuer(ctx, "GET", id, "", nil)
}

func (c *Client) CreateIssuer(ctx context.Context, req CreateIssuerRequest) (*Issuer, error) {
	return c.issuer(ctx, "POST", "", "", req)
}

func (c *Client) UpdateIssuer(ctx context.Context, id string, req UpdateIssuerRequest) (*Issuer, error) {
	return c.issuer(ctx, "PATCH", id, "", req)
}

func (c *Client) RetireIssuer(ctx context.Context, id string, req RetireRequest) (*Issuer, error) {
	return c.issuer(ctx, "POST", id, "/retire", req)
}

func (c *Client) CancelRetirement(ctx context.Context, id string) (*Issuer, error) {
	return c.issuer(ctx, "DELETE", id, "/retire", nil)
}

func (c *Client) PostponeRetirement(ctx context.Context, id string, req PostponeRequest) (*Issuer, error) {
	return c.issuer(ctx, "POST", id, "/retire/postpone", req)
}

func (c *Client) ListAudit(ctx context.Context, issuerID string, limit int) ([]AuditEntry, error) {
	q := url.Values{"issuer_id": {issuerID}, "limit": {strconv.Itoa(limit)}}
	var out []AuditEntry
	err := c.do(ctx, "GET", "/v1/admin/audit?"+q.Encode(), nil, &out)
	return out, err
}
