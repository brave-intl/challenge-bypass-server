# Issuer Admin API + cbp-manage TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Signed `/v1/admin` API plus a bubbletea TUI (`cmd/cbp-manage`) to view, create, edit and retire/replace issuers, with retirement enforcing a replacement and a ≥90-day overlap, and no delete path.

**Architecture:** A cgo-free `adminapi/` package holds wire types, the status rule, the ed25519 request signer and an HTTP client; the server and TUI both import it. The server adds a bat-go `httpsignature` middleware (subscriptions support model), new tables `issuer_retirements` + `issuer_admin_audit` (migration 0008, `v3_issuers` untouched), admin DB functions, handlers, and a sign-path gate. The TUI is a thin bubbletea client over `adminapi.Client`.

**Tech Stack:** Go 1.24, chi v5, database/sql + lib/pq, golang-migrate, bat-go libs (`httpsignature`, `middleware`, `time`), golang.org/x/crypto/ssh, charmbracelet/bubbletea + bubbles + lipgloss, testify.

**Spec:** `docs/superpowers/specs/2026-09-30-issuer-admin-tui-design.md`

## Global Constraints

- No manual v1/v2 key rotation and no change to key ordering: HTTP redeem verifies only the newest v1/v2 key (`server/tokens.go:410,506`), so adding keys breaks outstanding tokens. Rotation = create replacement + retire.
- Issuers are never deleted. No SQL `DELETE FROM v3_issuers` / `v3_issuer_keys` is added. The only DELETE added is of an `issuer_retirements` row on cancel.
- `v3_issuers` schema is not altered (old pods run `SELECT i.*` with a 14-column scan).
- Retirement overlap: `stop_redeeming_at >= stop_issuing_at + 90 days` (`adminapi.MinRetirementOverlap = 90 * 24 * time.Hour`).
- Admin signature: ed25519, headers `date digest (request-target)`, ±10 min (bat-go default), keyId = hex raw public key.
- Unknown `ENV` → empty allowlist + warning, never a startup failure.
- Rollout is three releases (runbook: `docs/issuer-admin-rollout.md`): R0 = Task 0 alone; R1 = Tasks 1–10 with `prodAdminKeys` empty; R2 = operator keys. Task 0 must be shippable on its own.
- Existing endpoints keep byte-for-byte behavior (the `txCreateV3Issuer` extraction is a pure refactor).
- Signing keys are never serialized by any admin response.
- Admin request bodies capped at 1 MiB.
- No git commits by the agent in this repo: stage and report; the user commits (they sign on another machine).
- Server package needs the Rust ristretto static lib: all `server/` and `kafka/` tests run via `make docker-test` (or the docker compose command it wraps). `adminapi/` and `cmd/cbp-manage/` tests run with plain `go test`.

## Review Focus

1. Retire with a replacement that is itself retiring → 422 (replacement must be `active`); test in Task 5.
2. v1/v2 issuer whose `expires_at` is the `0001-01-01` "no expiry" sentinel: shown as no expiry, PATCH to a date rejected as shortening, retire stores and cancel restores the sentinel; tests in Task 5.
3. Retire at "now" and immediately sign via HTTP v1, v2 and Kafka → rejected; bulk redeem for that issuer still succeeds; tests in Task 6.
4. Signed request whose path has a query string (`/v1/admin/audit?issuer_id=…&limit=5`) verifies; tampered query fails; tests in Task 3.
5. Operator's clock skewed > 10 min → TUI shows the skew hint, not a raw 408/425; test in Task 8.

---

### Task 0: Migration guard (release R0, ships alone)

**Files:**
- Modify: `server/db.go` (`InitDB`, the `m.Migrate(7)` block)
- Test: `server/migrate_guard_test.go` (`//go:build db`)

**Interfaces:**
- Produces: `const schemaVersion uint = 7` (Task 2 bumps to 8); `func migrateSchema(m *migrate.Migrate, target uint, logger *slog.Logger) error`

Why: golang-migrate's `Migrate(n)` fails when the DB's current version has no file in the image, so today any older image panics at startup against a newer schema (rollback = outage). After this, an image only migrates forward.

- [ ] **Step 1: Failing test** — `server/migrate_guard_test.go`

```go
//go:build db

package server

import (
	"log/slog"
	"os"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/stretchr/testify/require"
)

func TestMigrateSchemaSkipsWhenDBAhead(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.InitDBConfig())
	srv.InitDB(slog.New(slog.DiscardHandler)) // DB now at schemaVersion

	driver, err := postgres.WithInstance(srv.db, &postgres.Config{})
	require.NoError(t, err)
	m, err := migrate.NewWithDatabaseInstance("file:///src/migrations", "postgres", driver)
	require.NoError(t, err)

	// An "older image" targeting a lower version must not error or migrate down.
	require.NoError(t, migrateSchema(m, schemaVersion-1, slog.New(slog.DiscardHandler)))
	v, dirty, err := m.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, schemaVersion, v)

	// Same version: no-op.
	require.NoError(t, migrateSchema(m, schemaVersion, slog.New(slog.DiscardHandler)))
	_ = os.Getenv // keep import set stable if unused
}
```

- [ ] **Step 2: Implement** — in `server/db.go` add:

```go
// schemaVersion is the migration version this build needs.
const schemaVersion uint = 7

// migrateSchema migrates up to target, and never down: when the database is
// already at or past target (a newer release ran, then this one was rolled
// back to), it logs and returns. Plain m.Migrate(target) would fail there
// because the newer migration files are not in this image.
func migrateSchema(m *migrate.Migrate, target uint, logger *slog.Logger) error {
	v, dirty, err := m.Version()
	if err == nil && !dirty && v >= target {
		logger.Info("database schema at or ahead of this build; skipping migrations",
			"db_version", v, "build_version", target)
		return nil
	}
	if err := m.Migrate(target); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}
```

and replace in `InitDB`:

```go
	err = m.Migrate(7)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}
```

with

```go
	if err := migrateSchema(m, schemaVersion, logger); err != nil {
		panic(err)
	}
```

(Keep the surrounding code as is; check the exact existing lines before editing.)

- [ ] **Step 3: Run** — `make docker-test`. Expected: PASS, no regressions.

- [ ] **Step 4: Stage** — `git add server/db.go server/migrate_guard_test.go`. Report to the user that Task 0 is releasable alone as R0 before continuing.

---

### Task 1: `adminapi` types, status rule, signer, client

**Files:**
- Create: `adminapi/types.go`, `adminapi/sign.go`, `adminapi/client.go`
- Test: `adminapi/adminapi_test.go`
- Modify: `go.mod`, `go.sum` (`golang.org/x/crypto` direct)

**Interfaces:**
- Produces:
  - `const MinRetirementOverlap time.Duration`
  - `type Status string`; `StatusActive|StatusRetiring|StatusRetired|StatusExpired`
  - `func DeriveStatus(now time.Time, expiresAt, stopIssuingAt *time.Time) Status`
  - `type Key`, `type Issuer`, `type ListIssuersResponse`, `type CreateIssuerRequest`, `type UpdateIssuerRequest`, `type RetireRequest`, `type PostponeRequest`, `type AuditEntry`, `type AuditResponse` (fields below)
  - `func SignRequest(r *http.Request, body []byte, key ed25519.PrivateKey, now time.Time)`
  - `func LoadPrivateKey(path string) (ed25519.PrivateKey, error)`
  - `type Client struct{ BaseURL string; Key ed25519.PrivateKey; HTTP *http.Client }` with `ListIssuers`, `GetIssuer`, `CreateIssuer`, `UpdateIssuer`, `RetireIssuer`, `CancelRetirement`, `PostponeRetirement`, `ListAudit`
  - `type APIError struct{ Status int; Message string }`

- [ ] **Step 1: Write the failing tests** — `adminapi/adminapi_test.go`

```go
package adminapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDeriveStatus(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		name          string
		expires, stop *time.Time
		want          Status
	}{
		{"no expiry, not retired", nil, nil, StatusActive},
		{"future expiry", &future, nil, StatusActive},
		{"expired", &past, nil, StatusExpired},
		{"expired wins over retired", &past, &past, StatusExpired},
		{"retiring", &future, &future, StatusRetiring},
		{"retired redeem-only", &future, &past, StatusRetired},
		{"stop exactly now is retired", &future, &now, StatusRetired},
	}
	for _, c := range cases {
		if got := DeriveStatus(now, c.expires, c.stop); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// verify re-derives the signing string the way bat-go's server does.
func verify(t *testing.T, r *http.Request, body []byte, pub ed25519.PublicKey) {
	t.Helper()
	sigHdr := r.Header.Get("Signature")
	m := regexp.MustCompile(`keyId="([0-9a-f]+)",algorithm="ed25519",headers="date digest \(request-target\)",signature="([^"]+)"`).FindStringSubmatch(sigHdr)
	if m == nil {
		t.Fatalf("bad Signature header: %q", sigHdr)
	}
	if m[1] != hex.EncodeToString(pub) {
		t.Fatalf("keyId mismatch")
	}
	sum := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	if r.Header.Get("Digest") != digest {
		t.Fatalf("digest mismatch")
	}
	signing := "date: " + r.Header.Get("Date") + "\ndigest: " + digest +
		"\n(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI()
	sig, _ := base64.StdEncoding.DecodeString(m[2])
	if !ed25519.Verify(pub, []byte(signing), sig) {
		t.Fatalf("signature does not verify")
	}
}

func TestSignRequestCoversQuery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := httptest.NewRequest("GET", "http://x/v1/admin/audit?issuer_id=abc&limit=5", nil)
	SignRequest(r, nil, priv, time.Now())
	verify(t, r, nil, pub)
	if _, err := time.Parse(time.RFC1123, r.Header.Get("Date")); err != nil {
		t.Fatalf("Date not RFC1123: %v", err)
	}
}

func TestClientSignsAndDecodesErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		verify(t, r, buf, pub)
		if r.Method == "POST" {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"message":"stop_redeeming_at must be at least 90 days after stop_issuing_at"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(ListIssuersResponse{Issuers: []Issuer{{ID: "1", Name: "a", Status: StatusActive}}})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Key: priv}

	iss, err := c.ListIssuers(t.Context())
	if err != nil || len(iss) != 1 || iss[0].Name != "a" {
		t.Fatalf("list: %v %v", iss, err)
	}

	_, err = c.RetireIssuer(t.Context(), "1", RetireRequest{ReplacementIssuerID: "2"})
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Status != 422 || !strings.Contains(apiErr.Message, "90 days") {
		t.Fatalf("want 422 APIError, got %#v", err)
	}
	if !strings.Contains(string(gotBody), `"replacement_issuer_id":"2"`) {
		t.Fatalf("body not sent: %s", gotBody)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./adminapi/`
Expected: FAIL — `undefined: DeriveStatus` etc.

- [ ] **Step 3: Implement** — `adminapi/types.go`

```go
// Package adminapi holds the wire types, request signer and client for the
// challenge-bypass-server /v1/admin API. It must stay cgo-free so the
// cbp-manage TUI builds without the ristretto library.
package adminapi

import (
	"encoding/json"
	"time"
)

// MinRetirementOverlap is the minimum time a retired issuer keeps redeeming
// after it stops issuing, while its replacement issues.
const MinRetirementOverlap = 90 * 24 * time.Hour

type Status string

const (
	StatusActive   Status = "active"   // issuing and redeeming
	StatusRetiring Status = "retiring" // retirement scheduled, still issuing
	StatusRetired  Status = "retired"  // redeem-only
	StatusExpired  Status = "expired"  // neither
)

// DeriveStatus computes an issuer's status. A nil expiresAt means no expiry.
func DeriveStatus(now time.Time, expiresAt, stopIssuingAt *time.Time) Status {
	switch {
	case expiresAt != nil && expiresAt.Before(now):
		return StatusExpired
	case stopIssuingAt == nil:
		return StatusActive
	case stopIssuingAt.After(now):
		return StatusRetiring
	default:
		return StatusRetired
	}
}

type Key struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Cohort    int16      `json:"cohort"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	StartAt   *time.Time `json:"start_at,omitempty"`
	EndAt     *time.Time `json:"end_at,omitempty"`
}

type Issuer struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Version       int        `json:"version"`
	Cohort        int16      `json:"cohort"`
	MaxTokens     int        `json:"max_tokens"`
	Buffer        int        `json:"buffer"`
	Overlap       int        `json:"overlap"`
	Duration      *string    `json:"duration,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"` // nil = no expiry
	LastRotatedAt *time.Time `json:"last_rotated_at,omitempty"`
	Status        Status     `json:"status"`
	StopIssuingAt *time.Time `json:"stop_issuing_at,omitempty"`
	ReplacementID *string    `json:"replacement_issuer_id,omitempty"`
	RetiredBy     *string    `json:"retired_by,omitempty"`
	Replaces      []string   `json:"replaces,omitempty"`
	KeyCount      int        `json:"key_count"`
	LatestKeyEnd  *time.Time `json:"latest_key_end,omitempty"`
	Keys          []Key      `json:"keys,omitempty"`
}

type ListIssuersResponse struct {
	Issuers []Issuer `json:"issuers"`
}

type CreateIssuerRequest struct {
	Name      string     `json:"name"`
	Version   int        `json:"version"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ValidFrom *time.Time `json:"valid_from,omitempty"` // v3 only
	Duration  string     `json:"duration,omitempty"`   // v3 only, ISO 8601
	Buffer    int        `json:"buffer,omitempty"`     // v3 only
	Overlap   int        `json:"overlap,omitempty"`    // v3 only
}

// UpdateIssuerRequest: only these fields are mutable. The server rejects
// unknown fields.
type UpdateIssuerRequest struct {
	MaxTokens *int       `json:"max_tokens,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // extend only
}

type RetireRequest struct {
	ReplacementIssuerID string    `json:"replacement_issuer_id"`
	StopIssuingAt       time.Time `json:"stop_issuing_at"`
	StopRedeemingAt     time.Time `json:"stop_redeeming_at"`
}

// PostponeRequest moves stop_issuing_at later on a retiring or retired
// issuer (the emergency switch). StopRedeemingAt nil = server keeps the
// later of the current value and StopIssuingAt + 90 days.
type PostponeRequest struct {
	StopIssuingAt   time.Time  `json:"stop_issuing_at"`
	StopRedeemingAt *time.Time `json:"stop_redeeming_at,omitempty"`
}

type AuditEntry struct {
	ID        int64           `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	Operator  string          `json:"operator"`
	Action    string          `json:"action"`
	IssuerID  *string         `json:"issuer_id,omitempty"`
	Request   json.RawMessage `json:"request"`
}

type AuditResponse struct {
	Entries []AuditEntry `json:"entries"`
}
```

`adminapi/sign.go`

```go
package adminapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignRequest signs r the way bat-go's httpsignature verifier expects
// (same scheme as brave support-cli): ed25519 over date, digest and
// (request-target). body must be the exact bytes sent.
func SignRequest(r *http.Request, body []byte, key ed25519.PrivateKey, now time.Time) {
	r.Header.Set("Date", now.UTC().Format(http.TimeFormat))
	sum := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	r.Header.Set("Digest", digest)
	signing := strings.Join([]string{
		"date: " + r.Header.Get("Date"),
		"digest: " + digest,
		"(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI(),
	}, "\n")
	sig := ed25519.Sign(key, []byte(signing))
	pub := key.Public().(ed25519.PublicKey)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="%s",algorithm="ed25519",headers="date digest (request-target)",signature="%s"`,
		hex.EncodeToString(pub), base64.StdEncoding.EncodeToString(sig)))
}

// LoadPrivateKey reads an unencrypted OpenSSH ed25519 private key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	switch v := k.(type) {
	case *ed25519.PrivateKey:
		return *v, nil
	case ed25519.PrivateKey:
		return v, nil
	}
	return nil, errors.New("private key is not ed25519")
}
```

`adminapi/client.go`

```go
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
```

Then: `go get golang.org/x/crypto/ssh && go mod tidy` (tidy must not drop anything; if it errors because of cgo packages, use `go get` only).

- [ ] **Step 4: Run tests**

Run: `go test ./adminapi/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Stage**

```bash
git add adminapi go.mod go.sum
```

---

### Task 2: Migration 0008 + model `IsIssuing`

**Files:**
- Create: `migrations/0008_issuer_admin.up.sql`, `migrations/0008_issuer_admin.down.sql`
- Modify: `server/db.go` (`schemaVersion` 7 → 8), `model/issuer.go` (field + method)
- Test: `model/issuer_test.go` (append)

**Interfaces:**
- Produces: tables `issuer_retirements`, `issuer_admin_audit`; `model.Issuer.StopIssuingAt *time.Time`; `func (x *Issuer) IsIssuing(now time.Time) bool`

- [ ] **Step 1: Failing test** — append to `model/issuer_test.go`

```go
func TestIssuer_IsIssuing(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Second)
	assert.True(t, (&Issuer{}).IsIssuing(now))
	assert.True(t, (&Issuer{StopIssuingAt: &future}).IsIssuing(now))
	assert.False(t, (&Issuer{StopIssuingAt: &past}).IsIssuing(now))
	assert.False(t, (&Issuer{StopIssuingAt: &now}).IsIssuing(now))
}
```
(Check the file's existing imports; add `time` / `assert` if missing.)

- [ ] **Step 2: Implement**

`model/issuer.go` — add to `Issuer` struct after `Keys`:

```go
	// StopIssuingAt is set when the issuer is retired (issuer_retirements).
	// Loaded only on the sign path; nil means not retired.
	StopIssuingAt *time.Time `json:"-" db:"-"`
```

and method:

```go
// IsIssuing reports whether the issuer may still sign tokens at now.
func (x *Issuer) IsIssuing(now time.Time) bool {
	return x.StopIssuingAt == nil || now.Before(*x.StopIssuingAt)
}
```

`migrations/0008_issuer_admin.up.sql`:

```sql
-- v3_issuers is deliberately not altered: old pods scan `SELECT i.*` into a
-- fixed column list during rolling deploys.
CREATE TABLE issuer_retirements (
  issuer_id                uuid PRIMARY KEY REFERENCES v3_issuers(issuer_id),
  replacement_issuer_id    uuid NOT NULL REFERENCES v3_issuers(issuer_id),
  stop_issuing_at          timestamptz NOT NULL,
  expires_at_before_retire timestamptz NULL,
  retired_by               text NOT NULL,
  created_at               timestamptz NOT NULL DEFAULT now(),
  CHECK (issuer_id <> replacement_issuer_id)
);
CREATE INDEX issuer_retirements_replacement_idx ON issuer_retirements(replacement_issuer_id);

CREATE TABLE issuer_admin_audit (
  id         bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  operator   text NOT NULL,
  action     text NOT NULL,
  issuer_id  uuid NULL REFERENCES v3_issuers(issuer_id),
  request    jsonb NOT NULL
);
CREATE INDEX issuer_admin_audit_issuer_idx ON issuer_admin_audit(issuer_id, created_at);
```

`migrations/0008_issuer_admin.down.sql`:

```sql
DROP TABLE IF EXISTS issuer_admin_audit;
DROP TABLE IF EXISTS issuer_retirements;
```

`server/db.go`: `const schemaVersion uint = 7` → `8`.

`server/server_test.go` `SetupTest`: tables list becomes
`{"issuer_admin_audit", "issuer_retirements", "v3_issuer_keys", "v3_issuers", "redemptions"}` (children first, FK order).

- [ ] **Step 3: Run**

Run: `make docker-test` (full suite; migration applies on `InitDB`)
Expected: PASS, including `TestIssuer_IsIssuing`; no regressions.

- [ ] **Step 4: Stage** — `git add migrations/0008_* model/issuer.go model/issuer_test.go server/db.go server/server_test.go`

---

### Task 3: Admin auth — keystore, env selection, middleware, router mount

**Files:**
- Create: `server/admin_keys.go`
- Modify: `server/server.go` (add `adminKeys *adminKeystore` to `Server`; mount `/v1/admin` group in `setupRouter`)
- Test: `server/admin_keys_test.go` (no build tag; runs in docker-test)

**Interfaces:**
- Consumes: `adminapi.SignRequest`
- Produces:
  - `var prodAdminKeys, devAdminKeys []string` (authorized_keys lines, comment = email)
  - `func adminKeysForEnv(env string) []string` (nil for unknown env)
  - `func newAdminKeystore(lines []string) (*adminKeystore, error)`
  - `func (s *adminKeystore) operator(keyID string) string`
  - `func adminSignatureMwr(ks *adminKeystore) func(http.Handler) http.Handler`
  - `func adminOperator(r *http.Request, ks *adminKeystore) string`
  - `c.adminRoutes(r chi.Router)` registers handlers (handlers themselves in Task 7; this task registers only a `GET /v1/admin/whoami` probe used by tests and the TUI's connection check)

- [ ] **Step 1: Failing test** — `server/admin_keys_test.go`

```go
package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testOperatorKey(t *testing.T, email string) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	line := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub))) + " " + email
	return priv, line
}

func TestAdminKeysForEnv(t *testing.T) {
	require.Equal(t, prodAdminKeys, adminKeysForEnv("production"))
	require.Equal(t, devAdminKeys, adminKeysForEnv("staging"))
	require.Equal(t, devAdminKeys, adminKeysForEnv("localtest"))
	require.Nil(t, adminKeysForEnv("prod-typo"))
}

func TestNewAdminKeystoreRejectsBadLines(t *testing.T) {
	_, err := newAdminKeystore([]string{"not a key"})
	require.Error(t, err)
	_, line := testOperatorKey(t, "")
	_, err = newAdminKeystore([]string{line})
	require.Error(t, err, "missing email comment must be rejected")
}

func TestAdminSignatureMwr(t *testing.T) {
	priv, line := testOperatorKey(t, "op@brave.com")
	other, _ := testOperatorKey(t, "stranger@x")
	ks, err := newAdminKeystore([]string{line})
	require.NoError(t, err)

	h := adminSignatureMwr(ks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(adminOperator(r, ks)))
	}))

	send := func(method, target string, body []byte, key ed25519.PrivateKey, at time.Time, tamper func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, bytes.NewReader(body))
		adminapi.SignRequest(r, body, key, at)
		if tamper != nil {
			tamper(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := send("GET", "/v1/admin/audit?issuer_id=a&limit=5", nil, priv, time.Now(), nil)
	require.Equal(t, 200, w.Code)
	require.Equal(t, "op@brave.com", w.Body.String())

	w = send("POST", "/v1/admin/issuers", []byte(`{"name":"x"}`), priv, time.Now(), nil)
	require.Equal(t, 200, w.Code)

	require.Equal(t, 403, send("GET", "/v1/admin/issuers", nil, other, time.Now(), nil).Code, "unknown key")
	require.Equal(t, 403, send("GET", "/v1/admin/audit?limit=5", nil, priv, time.Now(), func(r *http.Request) {
		r.URL.RawQuery = "limit=500"
	}).Code, "tampered query")
	require.Equal(t, 403, send("POST", "/v1/admin/issuers", []byte(`{"name":"x"}`), priv, time.Now(), func(r *http.Request) {
		r.Body = httptestBody(`{"name":"y"}`)
	}).Code, "tampered body")
	require.Equal(t, 408, send("GET", "/v1/admin/issuers", nil, priv, time.Now().Add(-11*time.Minute), nil).Code, "stale date")
	require.Equal(t, 401, send("GET", "/v1/admin/issuers", nil, priv, time.Now(), func(r *http.Request) {
		r.Header.Del("Signature")
	}).Code)
}

func TestAdminEmptyKeystoreDeniesAll(t *testing.T) {
	priv, _ := testOperatorKey(t, "op@brave.com")
	ks, err := newAdminKeystore(nil)
	require.NoError(t, err)
	h := adminSignatureMwr(ks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest("GET", "/v1/admin/issuers", nil)
	adminapi.SignRequest(r, nil, priv, time.Now())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, 403, w.Code)
}
```

with helper in the same file:

```go
func httptestBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
```
(add `io`, `strings` imports).

- [ ] **Step 2: Implement** — `server/admin_keys.go`

```go
package server

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/brave-intl/bat-go/libs/httpsignature"
	"github.com/brave-intl/bat-go/libs/middleware"
	"golang.org/x/crypto/ssh"
)

// Operators allowed to call /v1/admin. One OpenSSH authorized_keys line per
// operator; the comment must be the operator's email (it is written to the
// audit log). Adding or removing an operator is a code change + deploy, the
// same model as the subscriptions support API.
var prodAdminKeys = []string{}

var devAdminKeys = []string{}

const maxAdminBodySize = 1 << 20

// adminKeysForEnv returns the operator allowlist for env. An unknown env gets
// nil, which denies every admin request, rather than failing startup.
func adminKeysForEnv(env string) []string {
	switch env {
	case "production":
		return prodAdminKeys
	// staging uses the dev list so R1 (empty prodAdminKeys) can be smoke
	// tested there before operators are enabled in production.
	case "staging", "development", "dev", "sandbox", "local", "localtest", "test":
		return devAdminKeys
	}
	return nil
}

type adminKey struct {
	email string
	pub   httpsignature.Ed25519PubKey
}

type adminKeystore struct {
	keys map[string]adminKey // hex raw public key -> operator
}

func newAdminKeystore(lines []string) (*adminKeystore, error) {
	ks := &adminKeystore{keys: map[string]adminKey{}}
	for _, line := range lines {
		pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("admin key %q: %w", line, err)
		}
		if pk.Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("admin key %q: not ed25519", line)
		}
		if comment == "" {
			return nil, fmt.Errorf("admin key %q: comment must be the operator email", line)
		}
		raw := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
		ks.keys[hex.EncodeToString(raw)] = adminKey{email: comment, pub: httpsignature.Ed25519PubKey(raw)}
	}
	return ks, nil
}

func (s *adminKeystore) LookupVerifier(ctx context.Context, keyID string) (context.Context, httpsignature.Verifier, error) {
	k, ok := s.keys[keyID]
	if !ok {
		return nil, nil, errors.New("admin: unknown operator key")
	}
	return ctx, k.pub, nil
}

func (s *adminKeystore) operator(keyID string) string {
	return s.keys[keyID].email
}

func adminSignatureMwr(ks *adminKeystore) func(http.Handler) http.Handler {
	verify := middleware.VerifyHTTPSignedOnly(httpsignature.ParameterizedKeystoreVerifier{
		SignatureParams: httpsignature.SignatureParams{
			Algorithm: httpsignature.ED25519,
			Headers:   []string{"date", "digest", "(request-target)"},
		},
		Keystore: ks,
		Opts:     crypto.Hash(0),
	})
	return func(next http.Handler) http.Handler {
		signed := verify(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodySize)
			signed.ServeHTTP(w, r)
		})
	}
}

// adminOperator returns the email of the operator who signed r.
func adminOperator(r *http.Request, ks *adminKeystore) string {
	keyID, err := middleware.GetKeyID(r.Context())
	if err != nil {
		return ""
	}
	return ks.operator(keyID)
}
```

`server/server.go`:
- `Server` struct: add `adminKeys *adminKeystore`.
- In `setupRouter`, before building routes:

```go
	adminLines := adminKeysForEnv(os.Getenv("ENV"))
	if adminLines == nil {
		logger.Warn("no admin operator keys for this ENV; /v1/admin will deny all requests", "env", os.Getenv("ENV"))
	}
	adminKeys, err := newAdminKeystore(adminLines)
	if err != nil {
		panic(err) // malformed hardcoded key: a code bug, caught by tests
	}
	c.adminKeys = adminKeys
```

- Inside the outer `r.Group` (after `r.Use(chiLogger)`, sibling of the "Authenticated Routes" group):

```go
		// Operator admin API: ed25519 signed requests in every environment.
		r.Route("/v1/admin", func(r chi.Router) {
			r.Use(adminSignatureMwr(c.adminKeys))
			c.adminRoutes(r)
		})
```

- Create `server/admin.go` with, for now:

```go
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (c *Server) adminRoutes(r chi.Router) {
	r.Method("GET", "/whoami", AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
		_ = RenderContent(map[string]string{"operator": adminOperator(r, c.adminKeys)}, w, http.StatusOK)
		return nil
	}))
}
```

- [ ] **Step 3: Run** — `make docker-test`. Expected: PASS including `TestAdminSignatureMwr`, `TestAdminEmptyKeystoreDeniesAll`.

- [ ] **Step 4: Stage** — `git add server/admin_keys.go server/admin_keys_test.go server/admin.go server/server.go go.mod go.sum`

---

### Task 4: Admin reads + audit + create (DB layer and tx refactor)

**Files:**
- Create: `server/admin_db.go`
- Modify: `server/db.go` — extract `txCreateV3Issuer` from `createV3Issuer` (fixes the rollback-masks-error defer)
- Test: `server/admin_db_test.go` (`//go:build db`)

**Interfaces:**
- Consumes: `adminapi` types, `txPopulateIssuerKeys`
- Produces:
  - `func txCreateV3Issuer(logger *slog.Logger, tx *sql.Tx, issuer model.Issuer) (uuid.UUID, error)`
  - `type adminRuleError struct{ msg string }` (→ 422), `var errAdminNotFound` (→ 404)
  - `func (c *Server) adminListIssuers(ctx context.Context, now time.Time) ([]adminapi.Issuer, error)`
  - `func (c *Server) adminGetIssuer(ctx context.Context, id uuid.UUID, now time.Time) (*adminapi.Issuer, error)`
  - `func (c *Server) adminCreateIssuer(ctx context.Context, operator string, req adminapi.CreateIssuerRequest) (uuid.UUID, error)`
  - `func txInsertAudit(ctx context.Context, tx *sql.Tx, operator, action string, issuerID *uuid.UUID, request any) error`
  - `func (c *Server) adminListAudit(ctx context.Context, issuerID *uuid.UUID, limit int) ([]adminapi.AuditEntry, error)`
  - `func nullableTime(t pq.NullTime) *time.Time` (zero/year≤1 → nil)

- [ ] **Step 1: Failing tests** — `server/admin_db_test.go`

```go
//go:build db

package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

type AdminDBSuite struct {
	suite.Suite
	srv *Server
	ctx context.Context
}

func TestAdminDBSuite(t *testing.T) { suite.Run(t, new(AdminDBSuite)) }

func (s *AdminDBSuite) SetupSuite() {
	s.srv = &Server{}
	s.Require().NoError(s.srv.InitDBConfig())
	s.srv.InitDB(slog.New(slog.DiscardHandler))
	s.srv.Logger = slog.New(slog.DiscardHandler)
	s.ctx = context.Background()
}

func (s *AdminDBSuite) SetupTest() {
	for _, t := range []string{"issuer_admin_audit", "issuer_retirements", "v3_issuer_keys", "v3_issuers"} {
		_, err := s.srv.db.Exec("delete from " + t)
		s.Require().NoError(err)
	}
}

func (s *AdminDBSuite) create(req adminapi.CreateIssuerRequest) uuid.UUID {
	id, err := s.srv.adminCreateIssuer(s.ctx, "op@brave.com", req)
	s.Require().NoError(err)
	return id
}

func v1(name string) adminapi.CreateIssuerRequest {
	return adminapi.CreateIssuerRequest{Name: name, Version: 1, Cohort: 1}
}

func v3(name string, expires time.Time) adminapi.CreateIssuerRequest {
	return adminapi.CreateIssuerRequest{Name: name, Version: 3, Cohort: 1, Duration: "P2M",
		Buffer: 2, Overlap: 1, ExpiresAt: &expires}
}

func (s *AdminDBSuite) TestCreateAndReadWritesAudit() {
	id := s.create(v1("ads-a"))

	got, err := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Require().NoError(err)
	s.Equal("ads-a", got.Name)
	s.Equal(1, got.Version)
	s.Equal(adminapi.StatusActive, got.Status)
	s.Nil(got.ExpiresAt, "0001-01-01 sentinel must read as no expiry")
	s.Len(got.Keys, 1)
	s.NotEmpty(got.Keys[0].ID)
	s.NotEmpty(got.Keys[0].PublicKey)

	list, err := s.srv.adminListIssuers(s.ctx, time.Now())
	s.Require().NoError(err)
	s.Len(list, 1)
	s.Equal(1, list[0].KeyCount)
	s.Empty(list[0].Keys, "list does not embed keys")

	audit, err := s.srv.adminListAudit(s.ctx, &id, 10)
	s.Require().NoError(err)
	s.Require().Len(audit, 1)
	s.Equal("create", audit[0].Action)
	s.Equal("op@brave.com", audit[0].Operator)
}

func (s *AdminDBSuite) TestCreateV3PopulatesWindows() {
	id := s.create(v3("skus-a", time.Now().AddDate(1, 0, 0)))
	got, err := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Require().NoError(err)
	s.Len(got.Keys, 3) // buffer + overlap
	s.NotNil(got.LatestKeyEnd)
}

func (s *AdminDBSuite) TestCreateDuplicateRollsBackAudit() {
	s.create(v1("dup"))
	_, err := s.srv.adminCreateIssuer(s.ctx, "op@brave.com", v1("dup"))
	s.Require().Error(err)
	audit, err := s.srv.adminListAudit(s.ctx, nil, 10)
	s.Require().NoError(err)
	s.Len(audit, 1, "failed create must not leave an audit row")
}

func (s *AdminDBSuite) TestCreateValidation() {
	for _, req := range []adminapi.CreateIssuerRequest{
		{Name: "", Version: 1},
		{Name: "x", Version: 4},
		{Name: "x", Version: 3, Duration: "", Buffer: 1},
		{Name: "x", Version: 3, Duration: "P1M", Buffer: 0},
		{Name: "x", Version: 1, ExpiresAt: ptrTime(time.Now().Add(-time.Hour))},
	} {
		_, err := s.srv.adminCreateIssuer(s.ctx, "op", req)
		var re *adminRuleError
		s.ErrorAs(err, &re, "%+v", req)
	}
}

func (s *AdminDBSuite) TestGetUnknown() {
	_, err := s.srv.adminGetIssuer(s.ctx, uuid.New(), time.Now())
	s.ErrorIs(err, errAdminNotFound)
}

func ptrTime(t time.Time) *time.Time { return &t }
```

- [ ] **Step 2: Refactor `createV3Issuer`** in `server/db.go` (replace lines 841–903):

```go
// createV3Issuer - creation of a v3 issuer
func (c *Server) createV3Issuer(issuer model.Issuer) (err error) {
	defer incrementTotal(createIssuerTotal)

	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// preserve the original error; a rollback failure must not mask it
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	queryTimer := prometheus.NewTimer(createTimeLimitedIssuerDBDuration)
	defer queryTimer.ObserveDuration()

	_, err = txCreateV3Issuer(c.Logger, tx, issuer)
	return err
}

// txCreateV3Issuer inserts the issuer and its initial keys on tx.
func txCreateV3Issuer(logger *slog.Logger, tx *sql.Tx, issuer model.Issuer) (uuid.UUID, error) {
	if issuer.MaxTokens == 0 {
		issuer.MaxTokens = 40
	}
	validFrom := issuer.ValidFrom
	if validFrom == nil {
		validFrom = ptr.FromTime(time.Now())
	}

	var issuerIDStr string
	err := tx.QueryRow(`
        INSERT INTO v3_issuers
            (issuer_type, issuer_cohort, max_tokens, version, expires_at,
             buffer, duration, overlap, valid_from)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING issuer_id`,
		issuer.IssuerType, issuer.IssuerCohort, issuer.MaxTokens, issuer.Version,
		issuer.ExpiresAt, issuer.Buffer, issuer.Duration, issuer.Overlap, validFrom,
	).Scan(&issuerIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get v3 issuer id: %w", err)
	}

	id, err := uuid.Parse(issuerIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse issuer id: %w", err)
	}
	issuer.ID = &id

	if err := txPopulateIssuerKeys(logger, tx, issuer); err != nil {
		return uuid.Nil, fmt.Errorf("failed to populate v3 issuer keys: %w", err)
	}
	return id, nil
}
```

Pure refactor: `txPopulateIssuerKeys` still receives the issuer exactly as before (its `ValidFrom` is not overwritten), so the existing `/v1|v2|v3/issuer` create endpoints behave identically.

- [ ] **Step 3: Implement** — `server/admin_db.go`

```go
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/brave-intl/challenge-bypass-server/model"
	timeutils "github.com/brave-intl/bat-go/libs/time"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var errAdminNotFound = errors.New("issuer not found")

// adminRuleError is a request that violates an admin rule (HTTP 422).
type adminRuleError struct{ msg string }

func (e *adminRuleError) Error() string { return e.msg }

func ruleErr(format string, args ...any) error {
	return &adminRuleError{msg: fmt.Sprintf(format, args...)}
}

// nullableTime maps NULL and the 0001-01-01 "no expiry" sentinel to nil.
func nullableTime(t pq.NullTime) *time.Time {
	if !t.Valid || t.Time.Year() <= 1 {
		return nil
	}
	v := t.Time
	return &v
}

const adminIssuerSelect = `
SELECT i.issuer_id, i.issuer_type, i.version, i.issuer_cohort, i.max_tokens,
       i.buffer, i.overlap, i.duration, i.created_at, i.valid_from, i.expires_at,
       i.last_rotated_at, r.stop_issuing_at, r.replacement_issuer_id, r.retired_by,
       (SELECT count(*) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id),
       (SELECT max(end_at) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id)
FROM v3_issuers i
LEFT JOIN issuer_retirements r ON r.issuer_id = i.issuer_id`

type rowScanner interface{ Scan(dest ...any) error }

func scanAdminIssuer(row rowScanner, now time.Time) (adminapi.Issuer, error) {
	var (
		out                                     adminapi.Issuer
		duration, replacement, retiredBy        sql.NullString
		created, validFrom, expires, rotated    pq.NullTime
		stopIssuing, latestEnd                  pq.NullTime
	)
	err := row.Scan(&out.ID, &out.Name, &out.Version, &out.Cohort, &out.MaxTokens,
		&out.Buffer, &out.Overlap, &duration, &created, &validFrom, &expires,
		&rotated, &stopIssuing, &replacement, &retiredBy, &out.KeyCount, &latestEnd)
	if err != nil {
		return out, err
	}
	if duration.Valid && duration.String != "" {
		out.Duration = &duration.String
	}
	if replacement.Valid {
		out.ReplacementID = &replacement.String
	}
	if retiredBy.Valid {
		out.RetiredBy = &retiredBy.String
	}
	out.CreatedAt = nullableTime(created)
	out.ValidFrom = nullableTime(validFrom)
	out.ExpiresAt = nullableTime(expires)
	out.LastRotatedAt = nullableTime(rotated)
	out.StopIssuingAt = nullableTime(stopIssuing)
	out.LatestKeyEnd = nullableTime(latestEnd)
	out.Status = adminapi.DeriveStatus(now, out.ExpiresAt, out.StopIssuingAt)
	return out, nil
}

func (c *Server) adminListIssuers(ctx context.Context, now time.Time) ([]adminapi.Issuer, error) {
	rows, err := c.db.QueryContext(ctx, adminIssuerSelect+` ORDER BY i.issuer_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminapi.Issuer{}
	for rows.Next() {
		iss, err := scanAdminIssuer(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, iss)
	}
	return out, rows.Err()
}

func (c *Server) adminGetIssuer(ctx context.Context, id uuid.UUID, now time.Time) (*adminapi.Issuer, error) {
	iss, err := scanAdminIssuer(c.db.QueryRowContext(ctx, adminIssuerSelect+` WHERE i.issuer_id = $1`, id), now)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errAdminNotFound
	}
	if err != nil {
		return nil, err
	}

	// Signing keys are never selected here.
	rows, err := c.db.QueryContext(ctx, `
        SELECT key_id, public_key, cohort, created_at, start_at, end_at
        FROM v3_issuer_keys WHERE issuer_id = $1
        ORDER BY end_at ASC NULLS FIRST, start_at ASC, created_at ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k adminapi.Key
		var pub sql.NullString
		var created, start, end pq.NullTime
		if err := rows.Scan(&k.ID, &pub, &k.Cohort, &created, &start, &end); err != nil {
			return nil, err
		}
		k.PublicKey = pub.String
		k.CreatedAt, k.StartAt, k.EndAt = nullableTime(created), nullableTime(start), nullableTime(end)
		iss.Keys = append(iss.Keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	replaced, err := c.db.QueryContext(ctx,
		`SELECT issuer_id FROM issuer_retirements WHERE replacement_issuer_id = $1 ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer replaced.Close()
	for replaced.Next() {
		var rid string
		if err := replaced.Scan(&rid); err != nil {
			return nil, err
		}
		iss.Replaces = append(iss.Replaces, rid)
	}
	return &iss, replaced.Err()
}

func txInsertAudit(ctx context.Context, tx *sql.Tx, operator, action string, issuerID *uuid.UUID, request any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO issuer_admin_audit (operator, action, issuer_id, request) VALUES ($1, $2, $3, $4)`,
		operator, action, issuerID, body)
	return err
}

func (c *Server) adminListAudit(ctx context.Context, issuerID *uuid.UUID, limit int) ([]adminapi.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := c.db.QueryContext(ctx, `
        SELECT id, created_at, operator, action, issuer_id, request
        FROM issuer_admin_audit
        WHERE ($1::uuid IS NULL OR issuer_id = $1)
        ORDER BY created_at DESC, id DESC LIMIT $2`, issuerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminapi.AuditEntry{}
	for rows.Next() {
		var e adminapi.AuditEntry
		var iid sql.NullString
		var req []byte
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Operator, &e.Action, &iid, &req); err != nil {
			return nil, err
		}
		if iid.Valid {
			e.IssuerID = &iid.String
		}
		e.Request = req
		out = append(out, e)
	}
	return out, rows.Err()
}

// withAdminTx runs fn in a transaction, rolling back on any error.
func (c *Server) withAdminTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()
	return fn(tx)
}

func validateCreate(req adminapi.CreateIssuerRequest, now time.Time) error {
	if strings.TrimSpace(req.Name) == "" {
		return ruleErr("name is required")
	}
	if req.Version < 1 || req.Version > 3 {
		return ruleErr("version must be 1, 2 or 3")
	}
	if req.MaxTokens < 0 {
		return ruleErr("max_tokens must be >= 0")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		return ruleErr("expires_at must be in the future")
	}
	if req.Version == 3 {
		if req.Duration == "" {
			return ruleErr("duration is required for v3")
		}
		if _, err := timeutils.ParseDuration(req.Duration); err != nil {
			return ruleErr("duration %q is not an ISO 8601 duration", req.Duration)
		}
		if req.Buffer < 1 || req.Overlap < 0 {
			return ruleErr("v3 needs buffer >= 1 and overlap >= 0")
		}
		if req.ExpiresAt == nil {
			return ruleErr("v3 issuers need expires_at (the rotation cron skips v3 issuers without one)")
		}
	} else if req.Duration != "" || req.Buffer != 0 || req.Overlap != 0 || req.ValidFrom != nil {
		return ruleErr("duration, buffer, overlap and valid_from are v3-only")
	}
	return nil
}

func (c *Server) adminCreateIssuer(ctx context.Context, operator string, req adminapi.CreateIssuerRequest) (uuid.UUID, error) {
	if err := validateCreate(req, time.Now()); err != nil {
		return uuid.Nil, err
	}
	cohort := req.Cohort
	if cohort == 0 {
		cohort = v1Cohort
	}
	iss := model.Issuer{
		IssuerType:   req.Name,
		IssuerCohort: cohort,
		MaxTokens:    req.MaxTokens,
		Version:      req.Version,
		ExpiresAt:    pq.NullTime{Valid: true}, // matches the existing "no expiry" encoding
	}
	if req.ExpiresAt != nil {
		iss.ExpiresAt.Time = *req.ExpiresAt
	}
	if req.Version == 3 {
		iss.Buffer, iss.Overlap, iss.ValidFrom = req.Buffer, req.Overlap, req.ValidFrom
		d := req.Duration
		iss.Duration = &d
	}

	var id uuid.UUID
	err := c.withAdminTx(ctx, func(tx *sql.Tx) error {
		var err error
		if id, err = txCreateV3Issuer(c.Logger, tx, iss); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "create", &id, req)
	})
	return id, err
}
```

- [ ] **Step 4: Run** — `make docker-test`. Expected: `AdminDBSuite` PASS; existing `ServerTestSuite` still PASS (tx refactor is behavior-preserving).

- [ ] **Step 5: Stage** — `git add server/admin_db.go server/admin_db_test.go server/db.go`

---

### Task 5: Update, retire, cancel, postpone (rules)

**Files:**
- Modify: `server/admin_db.go` (append)
- Test: `server/admin_db_test.go` (append)

**Interfaces:**
- Consumes: Task 4 helpers
- Produces:
  - `func (c *Server) adminUpdateIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.UpdateIssuerRequest) error`
  - `func (c *Server) adminRetireIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.RetireRequest, now time.Time) error`
  - `func (c *Server) adminCancelRetirement(ctx context.Context, operator string, id uuid.UUID, now time.Time) error`
  - `func (c *Server) adminPostponeRetirement(ctx context.Context, operator string, id uuid.UUID, req adminapi.PostponeRequest, now time.Time) error`

- [ ] **Step 1: Failing tests** — append to `server/admin_db_test.go`

```go
const day = 24 * time.Hour

func (s *AdminDBSuite) retire(id, repl uuid.UUID, stopIssuing, stopRedeeming time.Time) error {
	return s.srv.adminRetireIssuer(s.ctx, "op@brave.com", id, adminapi.RetireRequest{
		ReplacementIssuerID: repl.String(), StopIssuingAt: stopIssuing, StopRedeemingAt: stopRedeeming,
	}, time.Now())
}

func (s *AdminDBSuite) isRule(err error, contains string) {
	var re *adminRuleError
	s.Require().ErrorAs(err, &re)
	s.Contains(re.msg, contains)
}

func (s *AdminDBSuite) TestRetireHappyPathAndCancel() {
	old, repl := s.create(v1("old")), s.create(v1("new"))
	start := time.Now().Add(time.Hour)
	s.Require().NoError(s.retire(old, repl, start, start.Add(91*day)))

	got, _ := s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Equal(adminapi.StatusRetiring, got.Status)
	s.Equal(repl.String(), *got.ReplacementID)
	s.WithinDuration(start.Add(91*day), *got.ExpiresAt, time.Second)
	r, _ := s.srv.adminGetIssuer(s.ctx, repl, time.Now())
	s.Equal([]string{old.String()}, r.Replaces)

	s.Require().NoError(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now()))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Equal(adminapi.StatusActive, got.Status)
	s.Nil(got.ExpiresAt, "cancel restores the no-expiry sentinel")

	audit, _ := s.srv.adminListAudit(s.ctx, &old, 10)
	s.Equal("cancel_retire", audit[0].Action)
	s.Equal("retire", audit[1].Action)
}

func (s *AdminDBSuite) TestRetireRules() {
	now := time.Now()
	old, repl := s.create(v1("old")), s.create(v1("new"))
	start := now.Add(time.Minute)

	s.isRule(s.retire(old, old, start, start.Add(91*day)), "replacement")
	s.ErrorIs(s.retire(old, uuid.New(), start, start.Add(91*day)), errAdminNotFound)
	s.isRule(s.retire(old, repl, now.Add(-time.Hour), now.Add(91*day)), "stop_issuing_at")
	s.isRule(s.retire(old, repl, start, start.Add(89*day)), "90 days")

	// replacement expiring inside the overlap
	shortRepl := s.create(adminapi.CreateIssuerRequest{Name: "short", Version: 1, ExpiresAt: ptrTime(now.Add(30 * day))})
	s.isRule(s.retire(old, shortRepl, start, start.Add(91*day)), "replacement expires")

	// replacement that is itself retiring (Review Focus 1)
	third := s.create(v1("third"))
	s.Require().NoError(s.retire(repl, third, start, start.Add(91*day)))
	s.isRule(s.retire(old, repl, start, start.Add(91*day)), "replacement must be active")

	// already retiring target
	s.isRule(s.retire(repl, third, start, start.Add(91*day)), "already")
}

func (s *AdminDBSuite) TestRetireV3CoversFutureWindows() {
	old := s.create(v3("v3old", time.Now().AddDate(2, 0, 0))) // P2M, buffer 2, overlap 1
	repl := s.create(v1("v3new"))
	start := time.Now().Add(time.Minute)
	// 91 days < start + 6 months of windows → rejected
	s.isRule(s.retire(old, repl, start, start.Add(91*day)), "key window")
	s.Require().NoError(s.retire(old, repl, start, start.AddDate(0, 6, 2)))
}

func (s *AdminDBSuite) TestRetireReplacementNotYetValid() {
	old := s.create(v1("o"))
	later := time.Now().Add(10 * day)
	repl := s.create(adminapi.CreateIssuerRequest{Name: "r", Version: 3, Duration: "P1M", Buffer: 1,
		ValidFrom: &later, ExpiresAt: ptrTime(time.Now().AddDate(2, 0, 0))})
	start := time.Now().Add(time.Minute)
	s.isRule(s.retire(old, repl, start, start.Add(91*day)), "valid_from")
}

func (s *AdminDBSuite) TestChainRule() {
	a, b, c := s.create(v1("a")), s.create(v1("b")), s.create(v1("c"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(a, b, start, start.Add(100*day)))
	// b may not stop issuing before a stops redeeming
	s.isRule(s.retire(b, c, start.Add(time.Hour), start.Add(200*day)), "overlap promised")
	s.Require().NoError(s.retire(b, c, start.Add(100*day), start.Add(200*day)))
}

func (s *AdminDBSuite) TestCancelAfterStopIssuingRejected() {
	old, repl := s.create(v1("o2")), s.create(v1("r2"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(91*day)))
	s.isRule(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now().Add(time.Second)), "only while retiring")
}

func (s *AdminDBSuite) TestPostponeResumesIssuing() {
	old, repl := s.create(v1("pp-old")), s.create(v1("pp-new"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(91*day)))
	later := time.Now().Add(time.Second)
	got, _ := s.srv.adminGetIssuer(s.ctx, old, later)
	s.Require().Equal(adminapi.StatusRetired, got.Status)
	before := *got.ExpiresAt

	newStop := time.Now().Add(30 * day)
	s.Require().NoError(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop}, later))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, later)
	s.Equal(adminapi.StatusRetiring, got.Status, "issuing again")
	s.WithinDuration(newStop, *got.StopIssuingAt, time.Second)
	s.False(got.ExpiresAt.Before(newStop.Add(adminapi.MinRetirementOverlap).Add(-time.Second)), "redeem window pushed to keep 90 days")
	s.False(got.ExpiresAt.Before(before), "never shortens")

	iss, appErr := s.srv.GetLatestIssuer("pp-old", v1Cohort)
	s.Require().Nil(appErr)
	s.True(iss.IsIssuing(later))

	// earlier than current stop, shorter redemption, not retired → rejected
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: time.Now().Add(day)}, later), "later than")
	short := before.Add(-day)
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop.Add(day), StopRedeemingAt: &short}, later), "shorten")
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", repl, adminapi.PostponeRequest{StopIssuingAt: newStop}, later), "not retired")
}

func (s *AdminDBSuite) TestUpdateRules() {
	id := s.create(adminapi.CreateIssuerRequest{Name: "u", Version: 2, ExpiresAt: ptrTime(time.Now().Add(10 * day))})
	mt := 99
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{MaxTokens: &mt}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().Add(5 * day))}), "extend")
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().Add(20 * day))}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{}), "nothing to update")

	noExp := s.create(v1("noexp")) // Review Focus 2
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", noExp, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().AddDate(5, 0, 0))}), "no expiry")

	got, _ := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Equal(99, got.MaxTokens)
}
```

- [ ] **Step 2: Implement** — append to `server/admin_db.go`

```go
type lockedIssuer struct {
	id            uuid.UUID
	version       int
	buffer        int
	overlap       int
	duration      sql.NullString
	validFrom     pq.NullTime
	expiresAt     pq.NullTime
	stopIssuingAt *time.Time
}

func (l lockedIssuer) status(now time.Time) adminapi.Status {
	return adminapi.DeriveStatus(now, nullableTime(l.expiresAt), l.stopIssuingAt)
}

// txLockIssuers locks the given issuer rows in id order (deadlock-safe) and
// returns them keyed by id. Missing ids → errAdminNotFound.
func txLockIssuers(ctx context.Context, tx *sql.Tx, ids ...uuid.UUID) (map[uuid.UUID]*lockedIssuer, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT i.issuer_id, i.version, i.buffer, i.overlap, i.duration, i.valid_from, i.expires_at
        FROM v3_issuers i WHERE i.issuer_id = ANY($1)
        ORDER BY i.issuer_id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]*lockedIssuer{}
	for rows.Next() {
		l := &lockedIssuer{}
		if err := rows.Scan(&l.id, &l.version, &l.buffer, &l.overlap, &l.duration, &l.validFrom, &l.expiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		out[l.id] = l
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		l, ok := out[id]
		if !ok {
			return nil, errAdminNotFound
		}
		var stop pq.NullTime
		err := tx.QueryRowContext(ctx, `SELECT stop_issuing_at FROM issuer_retirements WHERE issuer_id = $1`, id).Scan(&stop)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		l.stopIssuingAt = nullableTime(stop)
	}
	return out, nil
}

func (c *Server) adminUpdateIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.UpdateIssuerRequest) error {
	if req.MaxTokens == nil && req.ExpiresAt == nil {
		return ruleErr("nothing to update: only max_tokens and expires_at are mutable")
	}
	if req.MaxTokens != nil && *req.MaxTokens < 0 {
		return ruleErr("max_tokens must be >= 0")
	}
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
		if err != nil {
			return err
		}
		l := locked[id]
		if req.ExpiresAt != nil {
			cur := nullableTime(l.expiresAt)
			if cur == nil {
				return ruleErr("issuer has no expiry; setting one would shorten it")
			}
			if !req.ExpiresAt.After(*cur) {
				return ruleErr("expires_at can only extend (current %s)", cur.UTC().Format(time.RFC3339))
			}
			if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, *req.ExpiresAt); err != nil {
				return err
			}
		}
		if req.MaxTokens != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET max_tokens = $2 WHERE issuer_id = $1`, id, *req.MaxTokens); err != nil {
				return err
			}
		}
		return txInsertAudit(ctx, tx, operator, "update", &id, req)
	})
}

// latestWindowEnd is the furthest v3 key end that can exist if the rotation
// cron keeps running until stopIssuing.
func latestWindowEnd(l *lockedIssuer, currentMax *time.Time, stopIssuing time.Time) (time.Time, error) {
	end := stopIssuing
	if l.duration.Valid && l.duration.String != "" {
		d, err := timeutils.ParseDuration(l.duration.String)
		if err != nil {
			return time.Time{}, err
		}
		for i := 0; i < l.buffer+l.overlap; i++ {
			next, err := d.From(end)
			if err != nil {
				return time.Time{}, err
			}
			end = *next
		}
	}
	if currentMax != nil && currentMax.After(end) {
		end = *currentMax
	}
	return end, nil
}

func (c *Server) adminRetireIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.RetireRequest, now time.Time) error {
	replID, err := uuid.Parse(req.ReplacementIssuerID)
	if err != nil {
		return ruleErr("replacement_issuer_id is not a uuid")
	}
	if replID == id {
		return ruleErr("replacement must be a different issuer")
	}
	stopIssuing, stopRedeeming := req.StopIssuingAt, req.StopRedeemingAt
	if stopIssuing.Before(now) && now.Sub(stopIssuing) <= time.Minute {
		stopIssuing = now // tolerate small client clock skew
	}
	if stopIssuing.Before(now) {
		return ruleErr("stop_issuing_at must not be in the past")
	}
	if stopRedeeming.Before(stopIssuing.Add(adminapi.MinRetirementOverlap)) {
		return ruleErr("stop_redeeming_at must be at least 90 days after stop_issuing_at")
	}

	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id, replID)
		if err != nil {
			return err
		}
		target, repl := locked[id], locked[replID]

		if st := target.status(now); st != adminapi.StatusActive {
			return ruleErr("issuer is already %s", st)
		}
		if st := repl.status(now); st != adminapi.StatusActive {
			return ruleErr("replacement must be active (it is %s)", st)
		}
		if exp := nullableTime(repl.expiresAt); exp != nil && exp.Before(stopRedeeming) {
			return ruleErr("replacement expires at %s, before stop_redeeming_at", exp.UTC().Format(time.RFC3339))
		}
		if vf := nullableTime(repl.validFrom); vf != nil && vf.After(stopIssuing) {
			return ruleErr("replacement valid_from %s is after stop_issuing_at", vf.UTC().Format(time.RFC3339))
		}

		// Chain rule: if the target is itself the replacement for an issuer
		// that still redeems, it must keep issuing until that one stops.
		var promised pq.NullTime
		err = tx.QueryRowContext(ctx, `
            SELECT max(i.expires_at) FROM issuer_retirements r
            JOIN v3_issuers i ON i.issuer_id = r.issuer_id
            WHERE r.replacement_issuer_id = $1 AND i.expires_at > $2`, id, now).Scan(&promised)
		if err != nil {
			return err
		}
		if p := nullableTime(promised); p != nil && stopIssuing.Before(*p) {
			return ruleErr("stop_issuing_at is before %s, the overlap promised to the issuer this one replaces", p.UTC().Format(time.RFC3339))
		}

		if target.version >= 3 {
			var maxEnd pq.NullTime
			if err := tx.QueryRowContext(ctx, `SELECT max(end_at) FROM v3_issuer_keys WHERE issuer_id = $1`, id).Scan(&maxEnd); err != nil {
				return err
			}
			need, err := latestWindowEnd(target, nullableTime(maxEnd), stopIssuing)
			if err != nil {
				return err
			}
			if stopRedeeming.Before(need) {
				return ruleErr("stop_redeeming_at must be at or after %s, the last key window that can be issued", need.UTC().Format(time.RFC3339))
			}
		}

		if _, err := tx.ExecContext(ctx, `
            INSERT INTO issuer_retirements
                (issuer_id, replacement_issuer_id, stop_issuing_at, expires_at_before_retire, retired_by)
            VALUES ($1, $2, $3, $4, $5)`,
			id, replID, stopIssuing, target.expiresAt, operator); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, stopRedeeming); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "retire", &id, req)
	})
}

// adminPostponeRetirement moves stop_issuing_at later on a retiring or
// retired issuer: the emergency switch when clients still depend on it.
// It never shortens redemption and keeps the replacement's promise.
func (c *Server) adminPostponeRetirement(ctx context.Context, operator string, id uuid.UUID, req adminapi.PostponeRequest, now time.Time) error {
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
		if err != nil {
			return err
		}
		l := locked[id]
		st := l.status(now)
		if l.stopIssuingAt == nil {
			return ruleErr("issuer is not retired")
		}
		if st == adminapi.StatusExpired {
			return ruleErr("issuer has expired; create a new issuer instead")
		}
		if !req.StopIssuingAt.After(*l.stopIssuingAt) || req.StopIssuingAt.Before(now) {
			return ruleErr("stop_issuing_at must be later than the current %s and not in the past", l.stopIssuingAt.UTC().Format(time.RFC3339))
		}
		cur := nullableTime(l.expiresAt) // retired issuers always have one
		redeem := req.StopIssuingAt.Add(adminapi.MinRetirementOverlap)
		if cur != nil && cur.After(redeem) {
			redeem = *cur
		}
		if req.StopRedeemingAt != nil {
			if cur != nil && req.StopRedeemingAt.Before(*cur) {
				return ruleErr("stop_redeeming_at would shorten redemption (current %s)", cur.UTC().Format(time.RFC3339))
			}
			if req.StopRedeemingAt.Before(req.StopIssuingAt.Add(adminapi.MinRetirementOverlap)) {
				return ruleErr("stop_redeeming_at must be at least 90 days after stop_issuing_at")
			}
			redeem = *req.StopRedeemingAt
		}
		// Replacement must still issue through the (possibly longer) window.
		var replExpires, replStop pq.NullTime
		err = tx.QueryRowContext(ctx, `
            SELECT i.expires_at, rr.stop_issuing_at
            FROM issuer_retirements r
            JOIN v3_issuers i ON i.issuer_id = r.replacement_issuer_id
            LEFT JOIN issuer_retirements rr ON rr.issuer_id = r.replacement_issuer_id
            WHERE r.issuer_id = $1`, id).Scan(&replExpires, &replStop)
		if err != nil {
			return err
		}
		if e := nullableTime(replExpires); e != nil && e.Before(redeem) {
			return ruleErr("replacement expires at %s, before the new stop_redeeming_at; extend it first", e.UTC().Format(time.RFC3339))
		}
		if s := nullableTime(replStop); s != nil && s.Before(redeem) {
			return ruleErr("replacement stops issuing at %s, before the new stop_redeeming_at; postpone it first", s.UTC().Format(time.RFC3339))
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issuer_retirements SET stop_issuing_at = $2 WHERE issuer_id = $1`, id, req.StopIssuingAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, redeem); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "postpone", &id, req)
	})
}

func (c *Server) adminCancelRetirement(ctx context.Context, operator string, id uuid.UUID, now time.Time) error {
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
		if err != nil {
			return err
		}
		if st := locked[id].status(now); st != adminapi.StatusRetiring {
			return ruleErr("retirement can be cancelled only while retiring (issuer is %s)", st)
		}
		var before pq.NullTime
		if err := tx.QueryRowContext(ctx,
			`DELETE FROM issuer_retirements WHERE issuer_id = $1 RETURNING expires_at_before_retire`, id).Scan(&before); err != nil {
			return err
		}
		// Never shorten: keep the later of the pre-retire value and the
		// current one; the no-expiry sentinel wins.
		restore := before
		if b, cur := nullableTime(before), nullableTime(locked[id].expiresAt); b != nil && cur != nil && cur.After(*b) {
			restore = locked[id].expiresAt
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, restore); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "cancel_retire", &id, map[string]string{"issuer_id": id.String()})
	})
}
```

- [ ] **Step 3: Run** — `make docker-test`. Expected: all `AdminDBSuite` tests PASS.

- [ ] **Step 4: Stage** — `git add server/admin_db.go server/admin_db_test.go`

---

### Task 6: Hot path — sign gate, rotation skip

**Files:**
- Modify: `server/db.go` — `fetchIssuersByCohort` loads `StopIssuingAt`; `rotateIssuers` + `rotateIssuersV3` queries add NOT EXISTS
- Modify: `server/tokens.go` — gate in `BlindedTokenIssuerHandlerV2`, `blindedTokenIssuerHandler`
- Modify: `kafka/signed_blinded_token_issuer_handler.go` — gate after `GetLatestIssuerKafka`
- Modify: `server/issuers.go` — `errIssuerRetired` + `retiredIssuerAppError()`
- Test: `server/admin_db_test.go` (append), `server/server_test.go` helpers reused

**Interfaces:**
- Consumes: `model.Issuer.IsIssuing`, `adminRetireIssuer`
- Produces: `var ErrIssuerRetired = errors.New("issuer is retired; use its replacement")` (exported, kafka uses it)

- [ ] **Step 1: Failing tests** — append to `server/admin_db_test.go`

```go
func (s *AdminDBSuite) TestSignPathSeesRetirement() {
	old, repl := s.create(v1("sgn")), s.create(v1("sgn-new"))
	iss, appErr := s.srv.GetLatestIssuer("sgn", v1Cohort)
	s.Require().Nil(appErr)
	s.True(iss.IsIssuing(time.Now()))

	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(91*day)))
	iss, appErr = s.srv.GetLatestIssuer("sgn", v1Cohort)
	s.Require().Nil(appErr, "lookup still works: bulk redeem uses it")
	s.False(iss.IsIssuing(time.Now().Add(time.Second)))

	k, err := s.srv.GetLatestIssuerKafka("sgn", v1Cohort)
	s.Require().NoError(err)
	s.False(k.IsIssuing(time.Now().Add(time.Second)))
}

func (s *AdminDBSuite) TestRotationCronsSkipRetired() {
	old := s.create(v3("cron3", time.Now().AddDate(2, 0, 0)))
	repl := s.create(v1("cronr"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().AddDate(0, 7, 0)))
	// force the cron's "needs keys" condition by removing future windows
	_, err := s.srv.db.Exec(`DELETE FROM v3_issuer_keys WHERE issuer_id = $1`, old)
	s.Require().NoError(err)
	_, err = s.srv.db.Exec(`INSERT INTO v3_issuer_keys (issuer_id, signing_key, public_key, cohort, start_at, end_at)
        VALUES ($1, 'x', 'y', 1, now() - interval '2 days', now() - interval '1 day')`, old)
	s.Require().NoError(err)
	time.Sleep(1100 * time.Millisecond) // stop_issuing_at now in the past
	s.Require().NoError(s.srv.rotateIssuersV3())
	var n int
	s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM v3_issuer_keys WHERE issuer_id = $1`, old).Scan(&n))
	s.Equal(1, n, "retired v3 issuer must not get new keys")
}
```

And in `server/server_test.go`, an HTTP-level test (Review Focus 3) using existing helpers:

```go
func (suite *ServerTestSuite) TestRetiredIssuerRejectsSignButRedeems() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	publicKey := suite.createIssuer(server.URL, "retire-me", v1Cohort)
	unblinded := suite.createToken(server.URL, "retire-me", publicKey)
	suite.createIssuer(server.URL, "retire-me-next", v1Cohort)

	var oldID, newID uuid.UUID
	suite.Require().NoError(suite.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type='retire-me'`).Scan(&oldID))
	suite.Require().NoError(suite.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type='retire-me-next'`).Scan(&newID))
	suite.Require().NoError(suite.srv.adminRetireIssuer(context.Background(), "op", oldID, adminapi.RetireRequest{
		ReplacementIssuerID: newID.String(), StopIssuingAt: time.Now(), StopRedeemingAt: time.Now().Add(91 * 24 * time.Hour),
	}, time.Now()))
	time.Sleep(1100 * time.Millisecond)

	// v1 sign rejected
	payload := fmt.Sprintf(`{"blinded_tokens":[%q]}`, suite.blindedTokenText())
	resp, err := suite.request("POST", server.URL+"/v1/blindedToken/retire-me", bytes.NewBufferString(payload))
	suite.Require().NoError(err)
	suite.Equal(http.StatusBadRequest, resp.StatusCode)
	// v2 sign rejected
	resp, err = suite.request("POST", server.URL+"/v2/blindedToken/retire-me", bytes.NewBufferString(payload))
	suite.Require().NoError(err)
	suite.Equal(http.StatusBadRequest, resp.StatusCode)

	// redeem of a token issued before retirement still succeeds
	preimage, sig := suite.prepareRedemption(unblinded, "m")
	resp, err = suite.attemptRedeem(server.URL, preimage, sig, "retire-me", "m")
	suite.Require().NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)
}
```

with helper (add near `createTokens`):

```go
func (suite *ServerTestSuite) blindedTokenText() string {
	tok, err := crypto.RandomToken()
	suite.Require().NoError(err)
	txt, err := tok.Blind().MarshalText()
	suite.Require().NoError(err)
	return string(txt)
}
```
(Check `createTokens` for the exact blind API used in this repo and mirror it.)

Kafka: in `kafka/main_test.go` or a new `kafka/signed_blinded_token_issuer_handler_test.go`, only if an existing test harness constructs `SignedBlindedTokenIssuerHandler` with a fake server; if none exists, the DB-level `TestSignPathSeesRetirement` plus the code review of the 6-line gate covers it — do not build a Kafka harness for this.

- [ ] **Step 2: Implement**

`server/issuers.go`, top-level:

```go
// ErrIssuerRetired is returned to sign requests for an issuer past its
// retirement stop_issuing_at. Sign requests are never routed to the
// replacement: the client stores tokens under the issuer it asked for.
var ErrIssuerRetired = errors.New("issuer is retired; use its replacement")

func retiredIssuerAppError(issuerType string) *AppError {
	return &AppError{Cause: ErrIssuerRetired, Message: "Issuer " + issuerType + " is retired; use its replacement", Code: http.StatusBadRequest}
}
```

`server/db.go` `fetchIssuersByCohort`, after `issuersWithKey, err := c.fetchIssuerKeys(...)` error check and before caching:

```go
	// Retirement lives in its own table (v3_issuers is not altered, see
	// migration 0008). One PK lookup per cache miss; cached with the issuer.
	for i := range issuersWithKey {
		var stop pq.NullTime
		err := c.dbr.QueryRow(`SELECT stop_issuing_at FROM issuer_retirements WHERE issuer_id = $1`,
			issuersWithKey[i].ID).Scan(&stop)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ProcessingErrorFromError(err, true)
		}
		if stop.Valid {
			t := stop.Time
			issuersWithKey[i].StopIssuingAt = &t
		}
	}
```

`rotateIssuers` WHERE clause: add line before `FOR UPDATE SKIP LOCKED`:

```sql
              AND NOT EXISTS (SELECT 1 FROM issuer_retirements r
                              WHERE r.issuer_id = v3_issuers.issuer_id AND r.stop_issuing_at <= now())
```

`rotateIssuersV3` WHERE clause: same line appended after the `max(end_at)` condition.

`server/tokens.go` — in `BlindedTokenIssuerHandlerV2` after the `GetLatestIssuer` error check, and in `blindedTokenIssuerHandler` after its `GetLatestIssuer` error check:

```go
		if !issuer.IsIssuing(time.Now()) {
			return retiredIssuerAppError(issuerType)
		}
```
(add `time` import if missing).

`kafka/signed_blinded_token_issuer_handler.go` — directly after the `if appErr != nil { … continue OUTER }` block following `GetLatestIssuerKafka`:

```go
		if !issuer.IsIssuing(time.Now()) {
			reqLogger.Warn("sign request for retired issuer", slog.Any("issuer", request.Issuer_type))
			metrics.CountError("issuer-retired")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerInvalid,
				Associated_data:   request.Associated_data,
			})
			continue OUTER
		}
```

- [ ] **Step 3: Run** — `make docker-test`. Expected: new tests PASS; all existing token/issuer/cron tests still PASS.

- [ ] **Step 4: Stage** — `git add server/db.go server/tokens.go server/issuers.go server/admin_db_test.go server/server_test.go kafka/signed_blinded_token_issuer_handler.go`

---

### Task 7: HTTP handlers + end-to-end signed API tests

**Files:**
- Modify: `server/admin.go` (replace the Task 3 stub body; keep `whoami`)
- Test: `server/admin_http_test.go` (`//go:build db`)

**Interfaces:**
- Consumes: Tasks 3–5; `adminapi.Client`
- Produces: routes under `/v1/admin`: `GET /whoami`, `GET /issuers`, `POST /issuers`, `GET /issuers/{id}`, `PATCH /issuers/{id}`, `POST /issuers/{id}/retire`, `DELETE /issuers/{id}/retire`, `POST /issuers/{id}/retire/postpone`, `GET /audit`

- [ ] **Step 1: Failing test** — `server/admin_http_test.go`

```go
//go:build db

package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/stretchr/testify/suite"
)

type AdminHTTPSuite struct {
	suite.Suite
	srv    *Server
	http   *httptest.Server
	client *adminapi.Client
}

func TestAdminHTTPSuite(t *testing.T) { suite.Run(t, new(AdminHTTPSuite)) }

func (s *AdminHTTPSuite) SetupSuite() {
	s.Require().NoError(os.Setenv("ENV", "localtest"))
	priv, line := testOperatorKey(s.T(), "op@brave.com")
	devAdminKeys = []string{line}
	s.T().Cleanup(func() { devAdminKeys = nil })

	s.srv = &Server{}
	s.Require().NoError(s.srv.InitDBConfig())
	s.srv.InitDB(slog.New(slog.DiscardHandler))
	_, h := s.srv.setupRouter(SetupLogger(context.Background(), "t", "t", "t"))
	s.http = httptest.NewServer(h)
	s.T().Cleanup(s.http.Close)
	s.client = &adminapi.Client{BaseURL: s.http.URL, Key: priv}
}

func (s *AdminHTTPSuite) SetupTest() {
	for _, t := range []string{"issuer_admin_audit", "issuer_retirements", "v3_issuer_keys", "v3_issuers"} {
		_, err := s.srv.db.Exec("delete from " + t)
		s.Require().NoError(err)
	}
}

func (s *AdminHTTPSuite) TestLifecycle() {
	ctx := context.Background()
	old, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-old", Version: 1})
	s.Require().NoError(err)
	s.Equal(adminapi.StatusActive, old.Status)
	repl, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-new", Version: 1})
	s.Require().NoError(err)

	_, err = s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-old", Version: 1})
	s.apiErr(err, 409)

	list, err := s.client.ListIssuers(ctx)
	s.Require().NoError(err)
	s.Len(list, 2)

	start := time.Now().Add(time.Hour)
	_, err = s.client.RetireIssuer(ctx, old.ID, adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: start, StopRedeemingAt: start.Add(10 * 24 * time.Hour)})
	s.apiErr(err, 422)

	got, err := s.client.RetireIssuer(ctx, old.ID, adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: start, StopRedeemingAt: start.Add(91 * 24 * time.Hour)})
	s.Require().NoError(err)
	s.Equal(adminapi.StatusRetiring, got.Status)

	got, err = s.client.CancelRetirement(ctx, old.ID)
	s.Require().NoError(err)
	s.Equal(adminapi.StatusActive, got.Status)

	audit, err := s.client.ListAudit(ctx, old.ID, 5)
	s.Require().NoError(err)
	s.Equal([]string{"cancel_retire", "retire", "create"}, actions(audit))
	s.Equal("op@brave.com", audit[0].Operator)

	_, err = s.client.GetIssuer(ctx, "00000000-0000-0000-0000-000000000000")
	s.apiErr(err, 404)
	_, err = s.client.GetIssuer(ctx, "not-a-uuid")
	s.apiErr(err, 400)
}

func (s *AdminHTTPSuite) TestPatchRejectsUnknownFields() {
	ctx := context.Background()
	iss, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "p", Version: 1})
	s.Require().NoError(err)
	// raw request with an immutable field
	type raw struct {
		Buffer int `json:"buffer"`
	}
	err = s.clientDo("PATCH", "/v1/admin/issuers/"+iss.ID, raw{Buffer: 3})
	s.apiErr(err, 422)
}

func (s *AdminHTTPSuite) TestNoSigningKeysInResponses() {
	ctx := context.Background()
	iss, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "leak", Version: 1})
	s.Require().NoError(err)
	req, _ := http.NewRequest("GET", s.http.URL+"/v1/admin/issuers/"+iss.ID, nil)
	adminapi.SignRequest(req, nil, s.client.Key, time.Now())
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var sb strings.Builder
	_, _ = io.Copy(&sb, resp.Body)
	s.NotContains(sb.String(), "signing_key")
	var signing []byte
	s.Require().NoError(s.srv.db.QueryRow(`SELECT signing_key FROM v3_issuer_keys LIMIT 1`).Scan(&signing))
	s.NotContains(sb.String(), string(signing))
}

func (s *AdminHTTPSuite) TestUnsignedRejected() {
	resp, err := http.Get(s.http.URL + "/v1/admin/issuers")
	s.Require().NoError(err)
	s.Equal(401, resp.StatusCode)
}

func (s *AdminHTTPSuite) apiErr(err error, status int) {
	var ae *adminapi.APIError
	s.Require().ErrorAs(err, &ae)
	s.Equal(status, ae.Status, ae.Message)
}

// clientDo sends an arbitrary signed JSON body (for invalid-shape tests).
func (s *AdminHTTPSuite) clientDo(method, path string, body any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, s.http.URL+path, bytes.NewReader(b))
	adminapi.SignRequest(req, b, s.client.Key, time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &adminapi.APIError{Status: resp.StatusCode}
	}
	return nil
}

func actions(es []adminapi.AuditEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Action
	}
	return out
}
```
(add `bytes`, `encoding/json`, `io` imports.)

- [ ] **Step 2: Implement** — `server/admin.go`

```go
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func (c *Server) adminRoutes(r chi.Router) {
	r.Method("GET", "/whoami", AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
		return c.adminRender(w, http.StatusOK, map[string]string{"operator": adminOperator(r, c.adminKeys)})
	}))
	r.Method("GET", "/issuers", AppHandler(c.adminListHandler))
	r.Method("POST", "/issuers", AppHandler(c.adminCreateHandler))
	r.Method("GET", "/issuers/{id}", AppHandler(c.adminGetHandler))
	r.Method("PATCH", "/issuers/{id}", AppHandler(c.adminUpdateHandler))
	r.Method("POST", "/issuers/{id}/retire", AppHandler(c.adminRetireHandler))
	r.Method("DELETE", "/issuers/{id}/retire", AppHandler(c.adminCancelRetireHandler))
	r.Method("POST", "/issuers/{id}/retire/postpone", AppHandler(c.adminPostponeHandler))
	r.Method("GET", "/audit", AppHandler(c.adminAuditHandler))
}

func (c *Server) adminRender(w http.ResponseWriter, status int, v any) *AppError {
	if err := RenderContent(v, w, status); err != nil {
		return WrapError(err, "Error encoding response", http.StatusInternalServerError)
	}
	return nil
}

// adminError maps DB-layer errors to HTTP.
func (c *Server) adminError(r *http.Request, err error) *AppError {
	var rule *adminRuleError
	var pqErr *pq.Error
	switch {
	case errors.As(err, &rule):
		return &AppError{Cause: err, Message: rule.msg, Code: http.StatusUnprocessableEntity}
	case errors.Is(err, errAdminNotFound):
		return &AppError{Cause: err, Message: "issuer not found", Code: http.StatusNotFound}
	case errors.As(err, &pqErr) && pqErr.Code == "23505":
		return &AppError{Cause: err, Message: "an issuer with that name already exists", Code: http.StatusConflict}
	}
	c.Logger.Error("admin request failed", slog.String("path", r.URL.Path), slog.Any("error", err))
	return &AppError{Cause: err, Message: "internal error", Code: http.StatusInternalServerError}
}

func adminIssuerID(r *http.Request) (uuid.UUID, *AppError) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, &AppError{Cause: err, Message: "id must be a uuid", Code: http.StatusBadRequest}
	}
	return id, nil
}

func decodeStrict(r *http.Request, v any) *AppError {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &AppError{Cause: err, Message: "invalid request body: " + err.Error(), Code: http.StatusUnprocessableEntity}
	}
	return nil
}

// respondIssuer re-reads the issuer after a mutation and renders it.
func (c *Server) respondIssuer(w http.ResponseWriter, r *http.Request, id uuid.UUID, status int) *AppError {
	c.invalidateIssuerCaches()
	iss, err := c.adminGetIssuer(r.Context(), id, time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, status, iss)
}

// invalidateIssuerCaches drops this pod's cached issuers. Other pods pick up
// changes within CACHE_DURATION_SECS.
func (c *Server) invalidateIssuerCaches() {
	if c.caches == nil {
		return
	}
	c.caches.Issuer.Clear()
	c.caches.Issuers.Clear()
	c.caches.IssuerCohort.Clear()
}

func (c *Server) logAdmin(r *http.Request, action string, id uuid.UUID) {
	c.Logger.Info("admin action", slog.String("operator", adminOperator(r, c.adminKeys)),
		slog.String("action", action), slog.String("issuer_id", id.String()))
}

func (c *Server) adminListHandler(w http.ResponseWriter, r *http.Request) *AppError {
	list, err := c.adminListIssuers(r.Context(), time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, adminapi.ListIssuersResponse{Issuers: list})
}

func (c *Server) adminGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	iss, err := c.adminGetIssuer(r.Context(), id, time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, iss)
}

func (c *Server) adminCreateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	var req adminapi.CreateIssuerRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	id, err := c.adminCreateIssuer(r.Context(), adminOperator(r, c.adminKeys), req)
	if err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "create", id)
	return c.respondIssuer(w, r, id, http.StatusCreated)
}

func (c *Server) adminUpdateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.UpdateIssuerRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminUpdateIssuer(r.Context(), adminOperator(r, c.adminKeys), id, req); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "update", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminRetireHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.RetireRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminRetireIssuer(r.Context(), adminOperator(r, c.adminKeys), id, req, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "retire", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminCancelRetireHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	if err := c.adminCancelRetirement(r.Context(), adminOperator(r, c.adminKeys), id, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "cancel_retire", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminPostponeHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.PostponeRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminPostponeRetirement(r.Context(), adminOperator(r, c.adminKeys), id, req, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "postpone", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminAuditHandler(w http.ResponseWriter, r *http.Request) *AppError {
	var issuerID *uuid.UUID
	if s := r.URL.Query().Get("issuer_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return &AppError{Cause: err, Message: "issuer_id must be a uuid", Code: http.StatusBadRequest}
		}
		issuerID = &id
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := c.adminListAudit(r.Context(), issuerID, limit)
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, adminapi.AuditResponse{Entries: entries})
}
```

`server/cache.go`: add

```go
// Clear removes every item.
func (c *SimpleCache[T]) Clear() {
	c.items.Clear()
}
```
(`sync.Map.Clear` exists since Go 1.23; go.mod is 1.24.)

- [ ] **Step 3: Run** — `make docker-test`. Expected: `AdminHTTPSuite` PASS.

- [ ] **Step 4: Stage** — `git add server/admin.go server/admin_http_test.go server/cache.go`

---

### Task 8: TUI — app shell, list, detail, audit, errors

**Files:**
- Create: `cmd/cbp-manage/main.go`, `cmd/cbp-manage/app.go`, `cmd/cbp-manage/styles.go`
- Test: `cmd/cbp-manage/app_test.go`
- Modify: `go.mod`/`go.sum` (`github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/bubbles`, `github.com/charmbracelet/lipgloss`)

**Interfaces:**
- Consumes: `adminapi.Client`, `adminapi.LoadPrivateKey`
- Produces:
  - `type api interface { ListIssuers; GetIssuer; CreateIssuer; UpdateIssuer; RetireIssuer; CancelRetirement; PostponeRetirement; ListAudit }` — method set of `*adminapi.Client` (lets tests use a fake; this is the one interface allowed since the fake is its second implementation)
  - `type model struct` (root bubbletea model) with `screen` enum: `screenList, screenDetail, screenCreate, screenEdit, screenRetire, screenConfirm`
  - `func newModel(c api) model`
  - `func describeErr(err error) string` (maps 401/403/408/425 to hints)
  - `type confirmReq struct{ title string; body any; typeToConfirm string; run func() tea.Cmd }`

- [ ] **Step 1: Failing tests** — `cmd/cbp-manage/app_test.go`

```go
package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type fakeAPI struct {
	issuers []adminapi.Issuer
	retired *adminapi.RetireRequest
	err     error
}

func (f *fakeAPI) ListIssuers(context.Context) ([]adminapi.Issuer, error) { return f.issuers, f.err }
func (f *fakeAPI) GetIssuer(_ context.Context, id string) (*adminapi.Issuer, error) {
	for _, i := range f.issuers {
		if i.ID == id {
			return &i, nil
		}
	}
	return nil, &adminapi.APIError{Status: 404, Message: "issuer not found"}
}
func (f *fakeAPI) CreateIssuer(context.Context, adminapi.CreateIssuerRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) UpdateIssuer(context.Context, string, adminapi.UpdateIssuerRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) RetireIssuer(_ context.Context, _ string, r adminapi.RetireRequest) (*adminapi.Issuer, error) {
	f.retired = &r
	return &f.issuers[0], nil
}
func (f *fakeAPI) CancelRetirement(context.Context, string) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) PostponeRetirement(context.Context, string, adminapi.PostponeRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) ListAudit(context.Context, string, int) ([]adminapi.AuditEntry, error) { return nil, nil }

func TestDescribeErrClockSkew(t *testing.T) {
	for _, st := range []int{408, 425} {
		msg := describeErr(&adminapi.APIError{Status: st, Message: "date is invalid"})
		if !strings.Contains(msg, "clock") {
			t.Errorf("%d: %q lacks clock hint", st, msg)
		}
	}
	if !strings.Contains(describeErr(&adminapi.APIError{Status: 403}), "not on the operator allowlist") {
		t.Error("403 hint missing")
	}
	if describeErr(errors.New("dial tcp: refused")) == "" {
		t.Error("network error must render")
	}
}

// drive runs a command chain synchronously (tests only).
func drive(m tea.Model, cmd tea.Cmd) tea.Model {
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			break
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, c := range batch {
				m = drive(m, c)
			}
			return m
		}
		m, cmd = m.Update(msg)
	}
	return m
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func typeText(m tea.Model, s string) tea.Model {
	for _, r := range s {
		// cmds dropped on purpose: textinput returns cursor-blink ticks
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func TestListLoadsAndShowsStatus(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "ads-a", Version: 1, Status: adminapi.StatusRetired}}}
	var m tea.Model = newModel(f)
	m = drive(m, m.Init())
	v := m.View()
	if !strings.Contains(v, "ads-a") || !strings.Contains(v, "retired") {
		t.Fatalf("list view missing issuer/status:\n%s", v)
	}
}
```

- [ ] **Step 2: Implement** — `cmd/cbp-manage/main.go`

```go
// cbp-manage is the operator TUI for challenge-bypass-server issuers.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

func main() {
	url := flag.String("url", os.Getenv("CBP_ADMIN_URL"), "server base URL (env CBP_ADMIN_URL)")
	keyPath := flag.String("private-key", os.Getenv("CBP_ADMIN_PRIVATE_KEY"), "OpenSSH ed25519 private key (env CBP_ADMIN_PRIVATE_KEY)")
	flag.Parse()
	if *url == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "cbp-manage: --url and --private-key (or CBP_ADMIN_URL / CBP_ADMIN_PRIVATE_KEY) are required")
		os.Exit(2)
	}
	key, err := adminapi.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cbp-manage:", err)
		os.Exit(1)
	}
	client := &adminapi.Client{BaseURL: *url, Key: key}
	if _, err := tea.NewProgram(newModel(client), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "cbp-manage:", err)
		os.Exit(1)
	}
}
```

`cmd/cbp-manage/styles.go`

```go
package main

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	helpStyle  = lipgloss.NewStyle().Faint(true)
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	statusStyle = map[adminapi.Status]lipgloss.Style{
		adminapi.StatusActive:   lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		adminapi.StatusRetiring: lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		adminapi.StatusRetired:  lipgloss.NewStyle().Foreground(lipgloss.Color("208")),
		adminapi.StatusExpired:  lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
)

func statusText(s adminapi.Status) string { return statusStyle[s].Render(string(s)) }
```

`cmd/cbp-manage/app.go` — root model, list + detail screens, error rendering, confirm screen. Full code:

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type api interface {
	ListIssuers(context.Context) ([]adminapi.Issuer, error)
	GetIssuer(context.Context, string) (*adminapi.Issuer, error)
	CreateIssuer(context.Context, adminapi.CreateIssuerRequest) (*adminapi.Issuer, error)
	UpdateIssuer(context.Context, string, adminapi.UpdateIssuerRequest) (*adminapi.Issuer, error)
	RetireIssuer(context.Context, string, adminapi.RetireRequest) (*adminapi.Issuer, error)
	CancelRetirement(context.Context, string) (*adminapi.Issuer, error)
	PostponeRetirement(context.Context, string, adminapi.PostponeRequest) (*adminapi.Issuer, error)
	ListAudit(context.Context, string, int) ([]adminapi.AuditEntry, error)
}

type screen int

const (
	screenList screen = iota
	screenDetail
	screenCreate
	screenEdit
	screenRetire
	screenConfirm
)

// messages
type issuersMsg []adminapi.Issuer
type detailMsg struct {
	iss   *adminapi.Issuer
	audit []adminapi.AuditEntry
}
type doneMsg struct {
	iss  *adminapi.Issuer
	note string
}
type errMsg struct{ err error }

// confirmReq is a pending mutation shown verbatim before it is sent.
type confirmReq struct {
	title         string
	body          any
	typeToConfirm string // non-empty: operator must type this exactly
	run           func() tea.Cmd
}

type model struct {
	api     api
	screen  screen
	issuers []adminapi.Issuer
	table   table.Model
	filter  string
	cur     *adminapi.Issuer
	audit   []adminapi.AuditEntry
	err     string
	note    string
	confirm *confirmReq
	confirmInput textinput.Model
	form    form   // Task 9
	retire  retireWizard // Task 9
	back    screen
	width   int
}

func newModel(c api) model {
	t := table.New(table.WithColumns([]table.Column{
		{Title: "Name", Width: 32}, {Title: "V", Width: 2}, {Title: "Cohort", Width: 6},
		{Title: "Status", Width: 9}, {Title: "Expires", Width: 17}, {Title: "Stop issuing", Width: 17},
	}), table.WithFocused(true), table.WithHeight(20))
	ti := textinput.New()
	ti.Placeholder = "type the issuer name to confirm"
	return model{api: c, table: t, confirmInput: ti}
}

func (m model) Init() tea.Cmd { return m.loadList() }

func (m model) loadList() tea.Cmd {
	return func() tea.Msg {
		l, err := m.api.ListIssuers(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return issuersMsg(l)
	}
}

func (m model) loadDetail(id string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		iss, err := m.api.GetIssuer(ctx, id)
		if err != nil {
			return errMsg{err}
		}
		audit, err := m.api.ListAudit(ctx, id, 20)
		if err != nil {
			return errMsg{err}
		}
		return detailMsg{iss, audit}
	}
}

// describeErr turns API errors into operator-facing text.
func describeErr(err error) string {
	var ae *adminapi.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 401:
			return "request was not signed (401)"
		case 403:
			return "signature rejected (403): your key is not on the operator allowlist for this environment, or the request was altered in transit"
		case 408, 425:
			return fmt.Sprintf("request date rejected (%d): your clock is more than 10 minutes off the server's; sync it (e.g. `timedatectl` / `sntp`)", ae.Status)
		}
		return fmt.Sprintf("%d: %s", ae.Status, ae.Message)
	}
	return err.Error()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func (m *model) rebuildTable() {
	rows := []table.Row{}
	for _, i := range m.visible() {
		rows = append(rows, table.Row{i.Name, fmt.Sprint(i.Version), fmt.Sprint(i.Cohort),
			string(i.Status), fmtTime(i.ExpiresAt), fmtTime(i.StopIssuingAt)})
	}
	m.table.SetRows(rows)
}

func (m model) visible() []adminapi.Issuer {
	if m.filter == "" {
		return m.issuers
	}
	out := []adminapi.Issuer{}
	for _, i := range m.issuers {
		if strings.Contains(strings.ToLower(i.Name), strings.ToLower(m.filter)) {
			out = append(out, i)
		}
	}
	return out
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.table.SetHeight(max(5, msg.Height-8))
		return m, nil
	case issuersMsg:
		m.issuers, m.err = msg, ""
		m.rebuildTable()
		return m, nil
	case detailMsg:
		m.cur, m.audit, m.err, m.screen = msg.iss, msg.audit, "", screenDetail
		return m, nil
	case doneMsg:
		m.note, m.err, m.confirm = msg.note, "", nil
		return m, tea.Batch(m.loadList(), m.loadDetail(msg.iss.ID))
	case errMsg:
		m.err = describeErr(msg.err)
		if m.screen == screenConfirm {
			m.screen, m.confirm = m.back, nil
		}
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenList:
		return m.updateList(msg)
	case screenDetail:
		return m.updateDetail(msg)
	case screenConfirm:
		return m.updateConfirm(msg)
	case screenCreate, screenEdit:
		return m.updateForm(msg) // Task 9
	case screenRetire:
		return m.updateRetire(msg) // Task 9
	}
	return m, nil
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "r":
		return m, m.loadList()
	case "n":
		return m.openCreate(), nil // Task 9
	case "enter":
		v := m.visible()
		if i := m.table.Cursor(); i >= 0 && i < len(v) {
			return m, m.loadDetail(v[i].ID)
		}
		return m, nil
	case "backspace":
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
			m.rebuildTable()
		}
		return m, nil
	case "up", "down", "k", "j", "pgup", "pgdown", "home", "end":
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
	if k.Type == tea.KeyRunes && k.String() != "/" {
		m.filter += string(k.Runes)
		m.rebuildTable()
	}
	return m, nil
}

func (m model) updateDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.cur == nil {
		return m, nil
	}
	cur := *m.cur
	switch k.String() {
	case "esc", "q":
		m.screen, m.note = screenList, ""
		return m, m.loadList()
	case "e":
		return m.openEdit(cur), nil // Task 9
	case "R":
		return m.openRetire(cur), nil // Task 9
	case "p":
		if cur.StopIssuingAt == nil || cur.Status == adminapi.StatusExpired {
			m.err = "postpone applies to a retiring or retired issuer"
			return m, nil
		}
		return m.openPostpone(cur), nil // Task 9
	case "c":
		if cur.Status != adminapi.StatusRetiring {
			m.err = "only a retiring issuer can have its retirement cancelled"
			return m, nil
		}
		return m.askConfirm(screenDetail, confirmReq{
			title:         "Cancel retirement of " + cur.Name,
			body:          map[string]string{"DELETE": "/v1/admin/issuers/" + cur.ID + "/retire"},
			typeToConfirm: cur.Name,
			run: func() tea.Cmd {
				return func() tea.Msg {
					iss, err := m.api.CancelRetirement(context.Background(), cur.ID)
					if err != nil {
						return errMsg{err}
					}
					return doneMsg{iss, "retirement cancelled"}
				}
			},
		}), nil
	}
	return m, nil
}

func (m model) askConfirm(back screen, req confirmReq) model {
	m.back, m.screen, m.confirm, m.err = back, screenConfirm, &req, ""
	m.confirmInput.SetValue("")
	if req.typeToConfirm != "" {
		m.confirmInput.Focus()
	}
	return m
}

func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "esc":
		m.screen, m.confirm = m.back, nil
		return m, nil
	case "enter":
		if m.confirm.typeToConfirm != "" && m.confirmInput.Value() != m.confirm.typeToConfirm {
			m.err = "typed name does not match"
			return m, nil
		}
		return m, m.confirm.run()
	}
	if m.confirm.typeToConfirm != "" {
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	switch m.screen {
	case screenList:
		b.WriteString(titleStyle.Render("Issuers") + "  filter: " + m.filter + "\n")
		b.WriteString(m.table.View() + "\n")
		b.WriteString(helpStyle.Render("enter open · type to filter · n new · r refresh · q quit"))
	case screenDetail:
		b.WriteString(m.detailView())
	case screenConfirm:
		body, _ := json.MarshalIndent(m.confirm.body, "", "  ")
		b.WriteString(titleStyle.Render(m.confirm.title) + "\n\n" + string(body) + "\n\n")
		if m.confirm.typeToConfirm != "" {
			b.WriteString("Type " + m.confirm.typeToConfirm + " to confirm:\n" + m.confirmInput.View() + "\n")
		}
		b.WriteString(helpStyle.Render("enter send · esc back"))
	case screenCreate, screenEdit:
		b.WriteString(m.formView()) // Task 9
	case screenRetire:
		b.WriteString(m.retireView()) // Task 9
	}
	if m.note != "" {
		b.WriteString("\n" + okStyle.Render(m.note))
	}
	if m.err != "" {
		b.WriteString("\n" + errStyle.Render(m.err))
	}
	return b.String()
}

func (m model) detailView() string {
	i := m.cur
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n\n", titleStyle.Render(i.Name), statusText(i.Status))
	fmt.Fprintf(&b, "id            %s\nversion       %d   cohort %d   max_tokens %d\n", i.ID, i.Version, i.Cohort, i.MaxTokens)
	if i.Version >= 3 {
		d := "—"
		if i.Duration != nil {
			d = *i.Duration
		}
		fmt.Fprintf(&b, "duration      %s   buffer %d   overlap %d\n", d, i.Buffer, i.Overlap)
	}
	fmt.Fprintf(&b, "created       %s\nvalid from    %s\nexpires       %s   (stops redeeming)\n",
		fmtTime(i.CreatedAt), fmtTime(i.ValidFrom), fmtTime(i.ExpiresAt))
	if i.StopIssuingAt != nil {
		by := ""
		if i.RetiredBy != nil {
			by = " by " + *i.RetiredBy
		}
		fmt.Fprintf(&b, "stop issuing  %s%s\nreplaced by   %s\n", fmtTime(i.StopIssuingAt), by, m.nameOf(i.ReplacementID))
	}
	for _, r := range i.Replaces {
		fmt.Fprintf(&b, "replaces      %s\n", m.nameOf(&r))
	}
	fmt.Fprintf(&b, "\nkeys (%d)\n", len(i.Keys))
	for _, k := range i.Keys {
		pk := k.PublicKey
		if len(pk) > 16 {
			pk = pk[:16] + "…"
		}
		fmt.Fprintf(&b, "  %s  %s → %s\n", pk, fmtTime(k.StartAt), fmtTime(k.EndAt))
	}
	b.WriteString("\naudit\n")
	for _, a := range m.audit {
		fmt.Fprintf(&b, "  %s  %-14s %s\n", a.CreatedAt.UTC().Format("2006-01-02 15:04Z"), a.Action, a.Operator)
	}
	b.WriteString("\n" + helpStyle.Render("e edit · R replace/retire · c cancel retirement · p postpone stop-issuing · esc back"))
	return b.String()
}

func (m model) nameOf(id *string) string {
	if id == nil {
		return "—"
	}
	for _, i := range m.issuers {
		if i.ID == *id {
			return i.Name + " (" + *id + ")"
		}
	}
	return *id
}
```

Temporary stubs so Task 8 compiles (replaced in Task 9) — `cmd/cbp-manage/forms.go`:

```go
package main

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type form struct{}
type retireWizard struct{}

func (m model) openCreate() model                          { return m }
func (m model) openEdit(adminapi.Issuer) model             { return m }
func (m model) openRetire(adminapi.Issuer) model           { return m }
func (m model) openPostpone(adminapi.Issuer) model         { return m }
func (m model) updateForm(tea.Msg) (tea.Model, tea.Cmd)    { return m, nil }
func (m model) updateRetire(tea.Msg) (tea.Model, tea.Cmd)  { return m, nil }
func (m model) formView() string                           { return "" }
func (m model) retireView() string                         { return "" }
```

Then `go get github.com/charmbracelet/bubbletea github.com/charmbracelet/bubbles github.com/charmbracelet/lipgloss`.

- [ ] **Step 3: Run** — `go test ./cmd/cbp-manage/ ./adminapi/ -v` and `go build ./cmd/cbp-manage`. Expected: PASS; binary builds without cgo (`CGO_ENABLED=0 go build ./cmd/cbp-manage` succeeds).

- [ ] **Step 4: Stage** — `git add cmd/cbp-manage go.mod go.sum`

---

### Task 9: TUI — create/edit forms and retire wizard

**Files:**
- Modify: `cmd/cbp-manage/forms.go` (replace stubs)
- Test: `cmd/cbp-manage/app_test.go` (append)

**Interfaces:**
- Consumes: Task 8 `model`, `askConfirm`, `confirmReq`, `doneMsg`, `errMsg`
- Produces:
  - `type field struct{ label string; input textinput.Model }`, `type form struct{ fields []field; focus int; submit func(model, []string) (model, error) }`
  - `type retireWizard struct{ target adminapi.Issuer; candidates []adminapi.Issuer; pick int; stopIssuing, stopRedeeming textinput.Model; step int }`
  - `func defaultRetireTimes(target adminapi.Issuer, now time.Time) (stopIssuing, stopRedeeming time.Time)`
  - `func parseWhen(s string, now time.Time) (time.Time, error)` — accepts `now`, RFC3339, `2006-01-02`, `+90d`

- [ ] **Step 1: Failing tests** — append to `cmd/cbp-manage/app_test.go`

```go
func TestDefaultRetireTimes(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	si, sr := defaultRetireTimes(adminapi.Issuer{Version: 1}, now)
	if !si.Equal(now) || !sr.Equal(now.Add(adminapi.MinRetirementOverlap)) {
		t.Fatalf("v1 defaults: %v %v", si, sr)
	}
	far := now.AddDate(0, 6, 0)
	d := "P1M"
	_, sr = defaultRetireTimes(adminapi.Issuer{Version: 3, LatestKeyEnd: &far, Duration: &d, Buffer: 2, Overlap: 1}, now)
	if sr.Before(far) {
		t.Fatalf("v3 default must cover latest key end, got %v", sr)
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"now":                  now,
		"+90d":                 now.Add(90 * 24 * time.Hour),
		"2027-01-01":           time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		"2027-01-01T05:00:00Z": time.Date(2027, 1, 1, 5, 0, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := parseWhen(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: got %v %v want %v", in, got, err, want)
		}
	}
	if _, err := parseWhen("tomorrow", now); err == nil {
		t.Error("garbage must error")
	}
}

func TestRetireWizardOffersOnlyActiveReplacementsAndRequiresTypedName(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{
		{ID: "1", Name: "old", Version: 1, Status: adminapi.StatusActive},
		{ID: "2", Name: "new", Version: 1, Status: adminapi.StatusActive},
		{ID: "3", Name: "gone", Version: 1, Status: adminapi.StatusRetired},
	}}
	var m tea.Model = newModel(f)
	m = drive(m, m.Init())
	m, _ = m.Update(key("enter")) // open "gone"? table sorted as given: row 0 = old
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("R"))
	mm := m.(model)
	if len(mm.retire.candidates) != 1 || mm.retire.candidates[0].ID != "2" {
		t.Fatalf("candidates: %+v", mm.retire.candidates)
	}
	// accept defaults through to confirm
	for i := 0; i < 3; i++ {
		m, _ = m.Update(key("enter"))
	}
	if m.(model).screen != screenConfirm {
		t.Fatalf("expected confirm screen, got %v", m.(model).screen)
	}
	m, _ = m.Update(key("enter")) // no typed name
	if f.retired != nil {
		t.Fatal("retire sent without typed confirmation")
	}
	m = typeText(m, "old")
	var cmd tea.Cmd
	m, cmd = m.Update(key("enter"))
	drive(m, cmd)
	if f.retired == nil || f.retired.ReplacementIssuerID != "2" {
		t.Fatalf("retire not sent correctly: %+v", f.retired)
	}
	if f.retired.StopRedeemingAt.Sub(f.retired.StopIssuingAt) < adminapi.MinRetirementOverlap {
		t.Fatal("default overlap below 90 days")
	}
}
```

- [ ] **Step 2: Implement** — replace `cmd/cbp-manage/forms.go`

```go
package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type field struct {
	label string
	input textinput.Model
}

type form struct {
	title  string
	fields []field
	focus  int
	// build validates the values and returns the confirm request to show.
	build func(m model, vals []string) (confirmReq, error)
}

func newField(label, value, placeholder string) field {
	ti := textinput.New()
	ti.SetValue(value)
	ti.Placeholder = placeholder
	return field{label: label, input: ti}
}

// parseWhen accepts "now", "+Nd", "YYYY-MM-DD" (UTC midnight) or RFC3339.
func parseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "now":
		return now, nil
	case strings.HasPrefix(s, "+") && strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(s[1 : len(s)-1])
		if err != nil {
			return time.Time{}, fmt.Errorf("bad relative time %q", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("time %q: use now, +90d, 2027-01-01 or RFC3339", s)
}

func optionalWhen(s string, now time.Time) (*time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	t, err := parseWhen(s, now)
	return &t, err
}

func atoiField(label, s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", label)
	}
	return n, nil
}

func (m model) openForm(s screen, f form) model {
	f.fields[0].input.Focus()
	m.form, m.screen, m.back, m.err, m.note = f, s, m.screen, "", ""
	return m
}

func (m model) openCreate() model {
	return m.openForm(screenCreate, form{
		title: "New issuer",
		fields: []field{
			newField("name", "", "issuer_type"),
			newField("version", "3", "1, 2 or 3"),
			newField("cohort", "1", ""),
			newField("max_tokens", "40", ""),
			newField("expires_at", "", "blank = none (v1/v2); required for v3"),
			newField("valid_from (v3)", "", "blank = now"),
			newField("duration (v3)", "P1M", "ISO 8601"),
			newField("buffer (v3)", "1", ""),
			newField("overlap (v3)", "0", ""),
		},
		build: func(m model, v []string) (confirmReq, error) {
			now := time.Now()
			req := adminapi.CreateIssuerRequest{Name: strings.TrimSpace(v[0])}
			var err error
			if req.Version, err = atoiField("version", v[1]); err != nil {
				return confirmReq{}, err
			}
			c, err := atoiField("cohort", v[2])
			if err != nil {
				return confirmReq{}, err
			}
			req.Cohort = int16(c)
			if req.MaxTokens, err = atoiField("max_tokens", v[3]); err != nil {
				return confirmReq{}, err
			}
			if req.ExpiresAt, err = optionalWhen(v[4], now); err != nil {
				return confirmReq{}, err
			}
			if req.Version == 3 {
				if req.ValidFrom, err = optionalWhen(v[5], now); err != nil {
					return confirmReq{}, err
				}
				req.Duration = strings.TrimSpace(v[6])
				if req.Buffer, err = atoiField("buffer", v[7]); err != nil {
					return confirmReq{}, err
				}
				if req.Overlap, err = atoiField("overlap", v[8]); err != nil {
					return confirmReq{}, err
				}
			}
			return confirmReq{
				title: "Create issuer " + req.Name,
				body:  req,
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.CreateIssuer(context.Background(), req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "created " + iss.Name}
					}
				},
			}, nil
		},
	})
}

func (m model) openEdit(cur adminapi.Issuer) model {
	exp := ""
	if cur.ExpiresAt != nil {
		exp = cur.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return m.openForm(screenEdit, form{
		title: "Edit " + cur.Name + " (only max_tokens and a later expires_at)",
		fields: []field{
			newField("max_tokens", strconv.Itoa(cur.MaxTokens), ""),
			newField("expires_at", exp, "later than current; blank = unchanged"),
		},
		build: func(m model, v []string) (confirmReq, error) {
			req := adminapi.UpdateIssuerRequest{}
			if mt, err := atoiField("max_tokens", v[0]); err != nil {
				return confirmReq{}, err
			} else if mt != cur.MaxTokens {
				req.MaxTokens = &mt
			}
			if strings.TrimSpace(v[1]) != exp && strings.TrimSpace(v[1]) != "" {
				t, err := parseWhen(v[1], time.Now())
				if err != nil {
					return confirmReq{}, err
				}
				if cur.ExpiresAt == nil || !t.After(*cur.ExpiresAt) {
					return confirmReq{}, fmt.Errorf("expires_at can only move later")
				}
				req.ExpiresAt = &t
			}
			if req.MaxTokens == nil && req.ExpiresAt == nil {
				return confirmReq{}, fmt.Errorf("nothing changed")
			}
			return confirmReq{
				title: "Update " + cur.Name,
				body:  req,
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.UpdateIssuer(context.Background(), cur.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "updated"}
					}
				},
			}, nil
		},
	})
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	f := &m.form
	switch k.String() {
	case "esc":
		m.screen = m.back
		return m, nil
	case "tab", "down":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus + 1) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	case "shift+tab", "up":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus + len(f.fields) - 1) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	case "enter":
		vals := make([]string, len(f.fields))
		for i := range f.fields {
			vals[i] = f.fields[i].input.Value()
		}
		req, err := f.build(m, vals)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		return m.askConfirm(m.screen, req), nil
	}
	var cmd tea.Cmd
	f.fields[f.focus].input, cmd = f.fields[f.focus].input.Update(msg)
	return m, cmd
}

func (m model) formView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.form.title) + "\n\n")
	for _, f := range m.form.fields {
		fmt.Fprintf(&b, "%-18s %s\n", f.label, f.input.View())
	}
	b.WriteString("\n" + helpStyle.Render("tab next · enter review · esc back"))
	return b.String()
}

func (m model) openPostpone(cur adminapi.Issuer) model {
	return m.openForm(screenEdit, form{
		title: "Postpone stop-issuing for " + cur.Name + " (resumes issuing; redemption only ever extends)",
		fields: []field{
			newField("stop_issuing_at", "+30d", "later than "+fmtTime(cur.StopIssuingAt)),
			newField("stop_redeeming_at", "", "blank = keep ≥ 90 days after stop issuing"),
		},
		build: func(m model, v []string) (confirmReq, error) {
			now := time.Now()
			si, err := parseWhen(v[0], now)
			if err != nil {
				return confirmReq{}, err
			}
			req := adminapi.PostponeRequest{StopIssuingAt: si}
			if req.StopRedeemingAt, err = optionalWhen(v[1], now); err != nil {
				return confirmReq{}, err
			}
			return confirmReq{
				title:         "Postpone stop-issuing for " + cur.Name,
				body:          req,
				typeToConfirm: cur.Name,
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.PostponeRetirement(context.Background(), cur.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "stop-issuing postponed"}
					}
				},
			}, nil
		},
	})
}

// ---- retire wizard ----

type retireWizard struct {
	target        adminapi.Issuer
	candidates    []adminapi.Issuer
	pick          int
	step          int // 0 pick replacement, 1 stop issuing, 2 stop redeeming
	stopIssuing   textinput.Model
	stopRedeeming textinput.Model
}

// defaultRetireTimes: stop issuing now; stop redeeming at the later of
// now+90d and (v3) the furthest key window the cron can still create.
func defaultRetireTimes(target adminapi.Issuer, now time.Time) (time.Time, time.Time) {
	sr := now.Add(adminapi.MinRetirementOverlap)
	if target.Version >= 3 {
		if target.LatestKeyEnd != nil && target.LatestKeyEnd.After(sr) {
			sr = *target.LatestKeyEnd
		}
		// ponytail: approximates the server's ISO-duration walk with 31-day
		// months; the server is authoritative and returns the exact minimum.
		if target.Duration != nil {
			if n, unit, ok := simpleISO(*target.Duration); ok {
				w := now.Add(time.Duration(n*(target.Buffer+target.Overlap)) * unit)
				if w.After(sr) {
					sr = w
				}
			}
		}
	}
	return now, sr
}

// simpleISO parses PnD / PnM / PnY / PTnH for the default only.
func simpleISO(d string) (int, time.Duration, bool) {
	units := map[string]time.Duration{"D": 24 * time.Hour, "M": 31 * 24 * time.Hour, "Y": 366 * 24 * time.Hour, "H": time.Hour}
	s := strings.TrimPrefix(strings.TrimPrefix(d, "P"), "T")
	if len(s) < 2 {
		return 0, 0, false
	}
	u, ok := units[s[len(s)-1:]]
	n, err := strconv.Atoi(s[:len(s)-1])
	return n, u, ok && err == nil
}

func (m model) openRetire(cur adminapi.Issuer) model {
	if cur.Status != adminapi.StatusActive {
		m.err = "only an active issuer can be retired (this one is " + string(cur.Status) + ")"
		return m
	}
	w := retireWizard{target: cur}
	for _, i := range m.issuers {
		if i.ID != cur.ID && i.Status == adminapi.StatusActive {
			w.candidates = append(w.candidates, i)
		}
	}
	if len(w.candidates) == 0 {
		m.err = "no active issuer to use as replacement: create one first (list → n)"
		return m
	}
	si, sr := defaultRetireTimes(cur, time.Now())
	w.stopIssuing = textinput.New()
	w.stopIssuing.SetValue(si.UTC().Format(time.RFC3339))
	w.stopRedeeming = textinput.New()
	w.stopRedeeming.SetValue(sr.UTC().Format(time.RFC3339))
	m.retire, m.back, m.screen, m.err, m.note = w, screenDetail, screenRetire, "", ""
	return m
}

func (m model) updateRetire(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	w := &m.retire
	switch k.String() {
	case "esc":
		if w.step == 0 {
			m.screen = screenDetail
		} else {
			w.step--
		}
		return m, nil
	case "enter":
		switch w.step {
		case 0:
			w.step = 1
			w.stopIssuing.Focus()
		case 1:
			w.stopIssuing.Blur()
			w.step = 2
			w.stopRedeeming.Focus()
		case 2:
			now := time.Now()
			si, err := parseWhen(w.stopIssuing.Value(), now)
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			sr, err := parseWhen(w.stopRedeeming.Value(), now)
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			if sr.Sub(si) < adminapi.MinRetirementOverlap {
				m.err = "stop redeeming must be at least 90 days after stop issuing"
				return m, nil
			}
			target, repl := w.target, w.candidates[w.pick]
			req := adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: si, StopRedeemingAt: sr}
			return m.askConfirm(screenRetire, confirmReq{
				title: fmt.Sprintf("Retire %s → replacement %s. %s stops issuing at %s and stops redeeming at %s. Clients must request %s from then on.",
					target.Name, repl.Name, target.Name, fmtTime(&si), fmtTime(&sr), repl.Name),
				body:          req,
				typeToConfirm: target.Name,
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.RetireIssuer(context.Background(), target.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "retirement scheduled"}
					}
				},
			}), nil
		}
		return m, nil
	case "up", "k":
		if w.step == 0 && w.pick > 0 {
			w.pick--
			return m, nil
		}
	case "down", "j":
		if w.step == 0 && w.pick < len(w.candidates)-1 {
			w.pick++
			return m, nil
		}
	}
	var cmd tea.Cmd
	switch w.step {
	case 1:
		w.stopIssuing, cmd = w.stopIssuing.Update(msg)
	case 2:
		w.stopRedeeming, cmd = w.stopRedeeming.Update(msg)
	}
	return m, cmd
}

func (m model) retireView() string {
	w := m.retire
	var b strings.Builder
	b.WriteString(titleStyle.Render("Retire "+w.target.Name) + "\n\n")
	b.WriteString("1. Replacement (active issuers only):\n")
	for i, c := range w.candidates {
		cursor := "  "
		if i == w.pick {
			cursor = "> "
		}
		fmt.Fprintf(&b, "%s%s (v%d, cohort %d, expires %s)\n", cursor, c.Name, c.Version, c.Cohort, fmtTime(c.ExpiresAt))
	}
	if w.step >= 1 {
		b.WriteString("\n2. Stop issuing at: " + w.stopIssuing.View() + "\n")
	}
	if w.step >= 2 {
		b.WriteString("3. Stop redeeming at (≥ 90 days later): " + w.stopRedeeming.View() + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("↑/↓ pick · enter next · esc back · times: now, +90d, 2027-01-01, RFC3339"))
	return b.String()
}
```

Also in `updateDetail` (Task 8 code), `openEdit`/`openRetire`/`openCreate` now return real screens; no change needed there.

- [ ] **Step 3: Run** — `go test ./cmd/cbp-manage/ -v`. Expected: PASS. Then manual smoke (optional, needs a running dev server): `go run ./cmd/cbp-manage --url http://localhost:2416 --private-key ~/.config/cbp-manage/id_ed25519`.

- [ ] **Step 4: Stage** — `git add cmd/cbp-manage`

---

### Task 10: Docs + operator onboarding

**Files:**
- Modify: `README.md` (new "Issuer admin API and cbp-manage" section)

- [ ] **Step 1: Write the section** covering, concisely:
  1. Generate a key: `ssh-keygen -t ed25519 -N "" -C you@brave.com -f ~/.config/cbp-manage/id_ed25519`.
  2. Onboard: add the `.pub` line to `prodAdminKeys` or `devAdminKeys` in `server/admin_keys.go` via PR; takes effect on deploy.
  3. Run: `CBP_ADMIN_URL=… CBP_ADMIN_PRIVATE_KEY=… go run ./cmd/cbp-manage` (or `go build ./cmd/cbp-manage`; no cgo needed).
  4. Retirement rules (copy the numbered list from spec §3 verbatim) and the client-coordination note: switch client configs to the replacement before `stop_issuing_at`; sign requests to a retired issuer are rejected, not routed.
  5. Endpoint table (method, path, purpose) from spec §4/§6.
  6. Link to `docs/issuer-admin-rollout.md` (rollout, rollback, break-glass).

- [ ] **Step 2: Final verification**

Run: `make docker-test` → PASS; `go test ./adminapi/ ./cmd/cbp-manage/` → PASS; `make lint` → no new findings in changed files.

- [ ] **Step 3: Stage** — `git add README.md docs/issuer-admin-rollout.md`; report to the user with a suggested commit message. Do not commit.
