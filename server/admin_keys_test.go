package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func httptestBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
