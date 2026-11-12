//go:build act

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// newACTTestServer needs a Postgres at DATABASE_URL; it runs only the ACT
// schema (plus uuid-ossp) so it does not depend on /src/migrations.
func newACTTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`); err != nil {
		t.Fatal(err)
	}
	if err := migrateACT(db); err != nil {
		t.Fatal(err)
	}
	c := &Server{db: db, dbr: db, Logger: slog.New(slog.DiscardHandler)}
	r := chi.NewRouter()
	c.mountACTRoutes(r)
	return c, r
}

func actDo(t *testing.T, h http.Handler, method, path string, body any, out any) int {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, rec.Body, err)
		}
	}
	return rec.Code
}

type actTestClient struct {
	t      *testing.T
	h      http.Handler
	base   string
	params string
	pk     []byte
}

func newACTIssuer(t *testing.T, h http.Handler, maxCredits uint64) *actTestClient {
	t.Helper()
	name := "leo-test-" + uuid.NewString()
	var iss actIssuerResponse
	code := actDo(t, h, "POST", "/v1/act/issuer", actIssuerCreateRequest{
		Name: name, MaxCredits: maxCredits, ExpiresAt: time.Now().Add(time.Hour),
	}, &iss)
	if code != http.StatusCreated {
		t.Fatalf("create issuer: %d", code)
	}
	return &actTestClient{t: t, h: h, base: "/v1/act/issuer/" + name, params: iss.Params, pk: iss.PublicKey}
}

func (c *actTestClient) credential(credits uint64) []byte {
	pre, req, err := act.ClientIssuanceRequest(c.params)
	if err != nil {
		c.t.Fatal(err)
	}
	var resp actIssueResponse
	if code := actDo(c.t, c.h, "POST", c.base+"/issue", actIssueRequest{Request: req, Credits: credits}, &resp); code != http.StatusOK {
		c.t.Fatalf("issue: %d", code)
	}
	token, err := act.ClientFinalizeIssuance(c.params, c.pk, pre, req, resp.Response)
	if err != nil {
		c.t.Fatal(err)
	}
	return token
}

func (c *actTestClient) balance(token []byte) uint64 {
	b, err := act.ClientBalance(token)
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

func TestACTHoldRefundLifecycle(t *testing.T) {
	_, h := newACTTestServer(t)
	cl := newACTIssuer(t, h, 1000)

	// Issuance is capped at max_credits.
	_, req, _ := act.ClientIssuanceRequest(cl.params)
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req, Credits: 1001}, nil); code != http.StatusBadRequest {
		t.Fatalf("over-max issue: %d, want 400", code)
	}

	token := cl.credential(1000)
	if cl.balance(token) != 1000 {
		t.Fatal("wrong initial balance")
	}

	// Hold 300.
	proof, prerefund, err := act.ClientProveSpend(cl.params, token, 300)
	if err != nil {
		t.Fatal(err)
	}
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}
	if held.Status != actStatusHeld || held.Charge != 300 {
		t.Fatalf("unexpected hold %+v", held)
	}

	// Identical retry is idempotent.
	var retry actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof}, &retry); code != http.StatusOK || retry.Nullifier != held.Nullifier {
		t.Fatalf("retry spend: %d %+v", code, retry)
	}

	// A second proof from the same credential is a double spend.
	proof2, _, _ := act.ClientProveSpend(cl.params, token, 1)
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof2}, nil); code != http.StatusConflict {
		t.Fatalf("double spend: %d, want 409", code)
	}

	refundPath := cl.base + "/spend/" + held.Nullifier + "/refund"
	cost := func(v uint64) actRefundRequest { return actRefundRequest{Cost: &v} }

	if code := actDo(t, h, "POST", refundPath, cost(301), nil); code != http.StatusBadRequest {
		t.Fatalf("cost > charge: %d, want 400", code)
	}

	// Settle at 120: 180 comes back.
	var settled actSpendResponse
	if code := actDo(t, h, "POST", refundPath, cost(120), &settled); code != http.StatusOK {
		t.Fatalf("refund: %d", code)
	}
	if settled.Status != actStatusRefunded || *settled.Cost != 120 || len(settled.Refund) == 0 {
		t.Fatalf("unexpected settlement %+v", settled)
	}
	next, err := act.ClientFinalizeRefund(cl.params, cl.pk, prerefund, proof, settled.Refund)
	if err != nil {
		t.Fatal(err)
	}
	if got := cl.balance(next); got != 880 {
		t.Fatalf("balance after refund = %d, want 880", got)
	}

	// Same cost again returns the stored refund; a different cost conflicts.
	var again actSpendResponse
	if code := actDo(t, h, "POST", refundPath, cost(120), &again); code != http.StatusOK || !bytes.Equal(again.Refund, settled.Refund) {
		t.Fatalf("idempotent refund: %d", code)
	}
	if code := actDo(t, h, "POST", refundPath, cost(100), nil); code != http.StatusConflict {
		t.Fatalf("conflicting refund: %d, want 409", code)
	}

	// The refund is retrievable by nullifier (lost-response recovery).
	var got actSpendResponse
	if code := actDo(t, h, "GET", cl.base+"/spend/"+held.Nullifier, nil, &got); code != http.StatusOK || !bytes.Equal(got.Refund, settled.Refund) {
		t.Fatalf("get spend: %d", code)
	}

	// The refunded credential spends normally.
	proof3, _, _ := act.ClientProveSpend(cl.params, next, 880)
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof3}, nil); code != http.StatusOK {
		t.Fatalf("spend refunded credential: %d", code)
	}
}

func TestACTRejects(t *testing.T) {
	_, h := newACTTestServer(t)
	a := newACTIssuer(t, h, 100)
	b := newACTIssuer(t, h, 100)

	// A credential from issuer a is not valid at issuer b.
	proof, _, _ := act.ClientProveSpend(a.params, a.credential(10), 5)
	if code := actDo(t, h, "POST", b.base+"/spend", actSpendRequest{Proof: proof}, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-issuer spend: %d, want 400", code)
	}
	if code := actDo(t, h, "POST", a.base+"/spend", actSpendRequest{Proof: []byte("junk")}, nil); code != http.StatusBadRequest {
		t.Fatalf("junk proof: %d, want 400", code)
	}
	if code := actDo(t, h, "GET", a.base+"/spend/nothex", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("bad nullifier: %d, want 400", code)
	}
	if code := actDo(t, h, "GET", a.base+fmt.Sprintf("/spend/%064x", 1), nil, nil); code != http.StatusNotFound {
		t.Fatalf("unknown nullifier: %d, want 404", code)
	}
	if code := actDo(t, h, "GET", "/v1/act/issuer/does-not-exist", nil, nil); code != http.StatusNotFound {
		t.Fatalf("unknown issuer: %d, want 404", code)
	}
}

func TestACTExpiredIssuerStillSettles(t *testing.T) {
	c, h := newACTTestServer(t)
	cl := newACTIssuer(t, h, 100)
	token := cl.credential(50)

	proof, _, _ := act.ClientProveSpend(cl.params, token, 20)
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}

	name := cl.base[len("/v1/act/issuer/"):]
	if _, err := c.db.Exec(`UPDATE act_issuers SET expires_at = now() - interval '1 minute' WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}

	_, req, _ := act.ClientIssuanceRequest(cl.params)
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req, Credits: 1}, nil); code != http.StatusBadRequest {
		t.Fatalf("issue after expiry: %d, want 400", code)
	}
	zero := uint64(0)
	if code := actDo(t, h, "POST", cl.base+"/spend/"+held.Nullifier+"/refund", actRefundRequest{Cost: &zero}, nil); code != http.StatusOK {
		t.Fatalf("settle after expiry: %d, want 200", code)
	}
}

func TestACTSweepAbandonedHolds(t *testing.T) {
	c, h := newACTTestServer(t)
	cl := newACTIssuer(t, h, 100)
	token := cl.credential(100)

	proof, prerefund, _ := act.ClientProveSpend(cl.params, token, 40)
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}

	// Fresh holds are left alone.
	if _, err := c.SweepACTHolds(context.Background(), time.Hour, 100); err != nil {
		t.Fatal(err)
	}
	var got actSpendResponse
	actDo(t, h, "GET", cl.base+"/spend/"+held.Nullifier, nil, &got)
	if got.Status != actStatusHeld {
		t.Fatalf("fresh hold swept: %+v", got)
	}

	if _, err := c.db.Exec(`UPDATE act_spends SET created_at = now() - interval '2 hours' WHERE spend_proof = $1`, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SweepACTHolds(context.Background(), time.Hour, 100); err != nil {
		t.Fatal(err)
	}

	actDo(t, h, "GET", cl.base+"/spend/"+held.Nullifier, nil, &got)
	if got.Status != actStatusRefunded || got.Cost == nil || *got.Cost != 0 {
		t.Fatalf("abandoned hold not settled at cost 0: %+v", got)
	}
	next, err := act.ClientFinalizeRefund(cl.params, cl.pk, prerefund, proof, got.Refund)
	if err != nil {
		t.Fatal(err)
	}
	if b := cl.balance(next); b != 100 {
		t.Fatalf("balance after sweep = %d, want 100", b)
	}
}
