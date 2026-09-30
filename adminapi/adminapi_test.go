package adminapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
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
		buf, _ := io.ReadAll(r.Body)
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

func TestClientWhoAmI(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verify(t, r, nil, pub)
		if r.URL.Path != "/v1/admin/whoami" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"operator":"op@brave.com"}`))
	}))
	defer srv.Close()
	got, err := (&Client{BaseURL: srv.URL, Key: priv}).WhoAmI(t.Context())
	if err != nil || got != "op@brave.com" {
		t.Fatalf("WhoAmI: %q %v", got, err)
	}
}
