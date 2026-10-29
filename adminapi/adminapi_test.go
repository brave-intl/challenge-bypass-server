package adminapi

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brave-intl/bat-go/libs/httpsignature"
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

// verify checks r's signature with bat-go's verifier, as the server does.
func verify(r *http.Request, pub ed25519.PublicKey) error {
	v := httpsignature.ParameterizedKeystoreVerifier{
		SignatureParams: httpsignature.SignatureParams{Algorithm: httpsignature.ED25519, Headers: []string{"date", "digest", "(request-target)"}},
		Keystore:        &httpsignature.StaticKeystore{Verifier: httpsignature.Ed25519PubKey(pub)},
		Opts:            crypto.Hash(0),
	}
	_, keyID, err := v.VerifyRequest(r)
	if err == nil && keyID != hex.EncodeToString(pub) {
		err = fmt.Errorf("keyId %q", keyID)
	}
	return err
}

func TestSignRequestCoversQuery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := httptest.NewRequest("GET", "http://x/v1/admin/audit?issuer_id=abc&limit=5", nil)
	if err := SignRequest(r, priv, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := verify(r, pub); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if _, err := time.Parse(time.RFC1123, r.Header.Get("Date")); err != nil {
		t.Fatalf("Date not RFC1123: %v", err)
	}
}

func TestClientSignsAndDecodesErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No t.Fatal here: this runs on the server's goroutine. A bad
		// signature fails the client calls below with a 401 instead.
		if err := verify(r, pub); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		buf, _ := io.ReadAll(r.Body)
		gotBody = buf
		if r.URL.Path == "/v1/admin/whoami" {
			_, _ = w.Write([]byte(`{"operator":"op-test"}`))
			return
		}
		if r.Method == "POST" {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"message":"stop_redeeming_at must be at least 90 days after stop_issuing_at"}`))
			return
		}
		_ = json.NewEncoder(w).Encode([]Issuer{{ID: "1", Name: "a", Status: StatusActive}})
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

	if got, err := c.WhoAmI(t.Context()); err != nil || got != "op-test" {
		t.Fatalf("WhoAmI: %q %v", got, err)
	}
}
