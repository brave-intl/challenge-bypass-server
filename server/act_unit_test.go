//go:build act

package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestACTDisabledRuntimeReturns501 verifies that when ACT_ENABLED is not "true",
// every ACT route (service and admin) returns 501 without touching Postgres.
func TestACTDisabledRuntimeReturns501(t *testing.T) {
	t.Setenv("ACT_ENABLED", "false")
	c := &Server{Logger: slog.New(slog.DiscardHandler)}
	r := chi.NewRouter()
	c.mountACTRoutes(r)
	r.Route("/v1/admin", func(r chi.Router) {
		r.Method("GET", "/act/issuers", AppHandler(c.actAdminIssuerListHandler))
		r.Method("POST", "/act/issuers", AppHandler(c.actAdminIssuerCreateHandler))
		r.Method("PATCH", "/act/issuers/{name}", AppHandler(c.actAdminIssuerUpdateHandler))
	})

	nullifier := fmt.Sprintf("%064x", 1)
	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/admin/act/issuers", ""},
		{http.MethodPost, "/v1/admin/act/issuers", `{"name":"leo","max_credits":10,"expires_at":"2030-01-01T00:00:00Z"}`},
		{http.MethodPatch, "/v1/admin/act/issuers/leo", `{"expires_at":"2030-01-02T00:00:00Z"}`},
		{http.MethodGet, "/v1/act/issuer/leo", ""},
		{http.MethodPost, "/v1/act/issuer/leo/issue", `{"request":"","credits":10,"idempotency_key":"k"}`},
		{http.MethodPost, "/v1/act/issuer/leo/rollover", `{"request":"","idempotency_key":"k","rollover":[{"proof":""}]}`},
		{http.MethodPost, "/v1/act/issuer/leo/spend", `{"proof":"","idempotency_key":"k"}`},
		{http.MethodGet, "/v1/act/issuer/leo/spend/" + nullifier, ""},
		{http.MethodPost, "/v1/act/issuer/leo/spend/" + nullifier + "/refund", `{"cost":0}`},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: status = %d, want 501; body %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}
