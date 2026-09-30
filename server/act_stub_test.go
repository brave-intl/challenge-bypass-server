//go:build !act

package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Without the "act" build tag the routes exist but report 501.
func TestACTUnavailableWithoutBuildTag(t *testing.T) {
	c := &Server{Logger: slog.New(slog.DiscardHandler)}
	r := chi.NewRouter()
	c.mountACTRoutes(r)

	body := `{"name":"leo","max_credits":10,"expires_at":"2999-01-01T00:00:00Z"}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/act/issuer", strings.NewReader(body)))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body %s", rec.Code, rec.Body)
	}
}
