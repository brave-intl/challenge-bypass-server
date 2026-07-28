package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	should "github.com/stretchr/testify/assert"
)

func TestIsSimpleTokenValid(t *testing.T) {
	list := []string{"valid-token-1", "valid-token-2"}

	tests := []struct {
		name  string
		list  []string
		token string
		exp   bool
	}{
		{name: "first_match", list: list, token: "valid-token-1", exp: true},
		{name: "second_match", list: list, token: "valid-token-2", exp: true},
		{name: "no_match", list: list, token: "not-a-token", exp: false},
		{name: "empty_token", list: list, token: "", exp: false},
		{name: "empty_list", list: nil, token: "anything", exp: false},
		{name: "empty_token_empty_list", list: nil, token: "", exp: false},
		// A prefix of a valid token must not authorize.
		{name: "prefix_of_valid", list: list, token: "valid-token-", exp: false},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			should.Equal(t, tc.exp, isSimpleTokenValid(tc.list, tc.token))
		})
	}
}

func TestBearerTokenMiddleware(t *testing.T) {
	tests := []struct {
		name   string
		header string // empty => no Authorization header set
		exp    string
	}{
		{name: "standard", header: "Bearer abc123", exp: "abc123"},
		{name: "lowercase_scheme", header: "bearer abc123", exp: "abc123"},
		{name: "uppercase_scheme", header: "BEARER abc123", exp: "abc123"},
		{name: "missing_header", header: "", exp: ""},
		{name: "scheme_only", header: "Bearer", exp: ""},
		{name: "scheme_and_space_only", header: "Bearer ", exp: ""},
		{name: "wrong_scheme", header: "Basic abc123", exp: ""},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var present bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, present = r.Context().Value(bearerTokenKey{}).(string)
			})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()

			BearerTokenMiddleware(next).ServeHTTP(rec, req)

			should.True(t, present, "token key must always be set in context")
			should.Equal(t, tc.exp, got)
		})
	}
}

func TestSimpleTokenAuthorizedOnly(t *testing.T) {
	orig := TokenList
	t.Cleanup(func() { TokenList = orig })
	TokenList = []string{"secret"}

	// Chain the two middlewares as the router does: BearerTokenMiddleware
	// populates the context that SimpleTokenAuthorizedOnly reads.
	handler := BearerTokenMiddleware(SimpleTokenAuthorizedOnly(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	))

	tests := []struct {
		name   string
		header string
		exp    int
	}{
		{name: "valid_token", header: "Bearer secret", exp: http.StatusOK},
		{name: "invalid_token", header: "Bearer wrong", exp: http.StatusForbidden},
		{name: "missing_header", header: "", exp: http.StatusForbidden},
		{name: "empty_token", header: "Bearer ", exp: http.StatusForbidden},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			should.Equal(t, tc.exp, rec.Code)
		})
	}
}
