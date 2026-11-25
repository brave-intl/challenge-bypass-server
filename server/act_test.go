//go:build db && act

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/go-chi/chi/v5"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type actTestEnv struct {
	srv      *Server
	handler  http.Handler
	adminKey ed25519.PrivateKey
}

// newACTTestServer needs a Postgres at DATABASE_URL. newACTTestServer runs the
// main and ACT migrations, so the admin audit table and the ACT tables exist.
func newACTTestServer(t *testing.T) *actTestEnv {
	t.Helper()
	t.Setenv("ACT_ENABLED", "true")
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL must be set for -tags=db")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	logger := slog.New(slog.DiscardHandler)
	mainMigrations, err := filepath.Abs("../migrations")
	if err != nil {
		t.Fatal(err)
	}
	mainDriver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+mainMigrations, "postgres", mainDriver)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateSchema(m, schemaVersion, logger); err != nil {
		t.Fatal(err)
	}
	if err := migrateACT(db, logger); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " op-act-test"
	ks, err := newAdminKeystore([]string{line})
	if err != nil {
		t.Fatal(err)
	}

	c := &Server{db: db, dbr: db, Logger: logger, adminKeys: ks, actCache: &actIssuerCache{}}
	r := chi.NewRouter()
	r.Use(BearerTokenMiddleware)
	r.Route("/v1/admin", func(r chi.Router) {
		r.Use(adminSignatureMwr(c.adminKeys))
		c.adminRoutes(r)
	})
	c.mountACTRoutes(r)
	return &actTestEnv{srv: c, handler: r, adminKey: priv}
}

func (e *actTestEnv) buildHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(BearerTokenMiddleware)
	r.Route("/v1/admin", func(r chi.Router) {
		r.Use(adminSignatureMwr(e.srv.adminKeys))
		e.srv.adminRoutes(r)
	})
	e.srv.mountACTRoutes(r)
	return r
}

func actDo(t *testing.T, h http.Handler, method, path string, body any, out any) int {
	t.Helper()
	return actDoWithHeaders(t, h, method, path, nil, nil, body, out)
}

func actDoAdmin(t *testing.T, env *actTestEnv, method, path string, body any, out any) int {
	t.Helper()
	return actDoWithHeaders(t, env.handler, method, path, env.adminKey, nil, body, out)
}

func actDoWithHeaders(t *testing.T, h http.Handler, method, path string, signKey ed25519.PrivateKey, headers map[string]string, body any, out any) int {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		switch v := body.(type) {
		case string:
			buf.WriteString(v)
		default:
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if signKey != nil {
		if err := adminapi.SignRequest(req, signKey, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, rec.Body, err)
		}
	}
	return rec.Code
}

type actTestClient struct {
	t      *testing.T
	env    *actTestEnv
	name   string
	base   string
	params string
	pk     []byte
}

func newACTIssuer(t *testing.T, env *actTestEnv, maxCredits uint64) *actTestClient {
	t.Helper()
	name := "leo-test-" + uuid.NewString()
	var iss actIssuerResponse
	code := actDoAdmin(t, env, "POST", "/v1/admin/act/issuers", actIssuerCreateRequest{
		Name: name, MaxCredits: maxCredits, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, &iss)
	if code != http.StatusCreated {
		t.Fatalf("create issuer: %d", code)
	}
	if iss.Context != name {
		t.Fatalf("issuer context = %q, want %q", iss.Context, name)
	}
	return &actTestClient{t: t, env: env, name: name, base: "/v1/act/issuer/" + name, params: iss.Params, pk: iss.PublicKey}
}

func (c *actTestClient) credential(credits uint64) []byte {
	pre, req, err := act.ClientIssuanceRequest(c.params)
	if err != nil {
		c.t.Fatal(err)
	}
	var resp actIssueResponse
	if code := actDo(c.t, c.env.handler, "POST", c.base+"/issue", actIssueRequest{
		Request: req, Credits: credits, IdempotencyKey: "iss-" + uuid.NewString(),
	}, &resp); code != http.StatusOK {
		c.t.Fatalf("issue: %d", code)
	}
	if resp.PurchasedCredits != credits || resp.RolledCredits != 0 || resp.TotalCredits != credits {
		c.t.Fatalf("unexpected issue totals: %+v", resp)
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
	env := newACTTestServer(t)
	h := env.handler
	cl := newACTIssuer(t, env, 1000)

	// Issuer appears in admin listing and GET exposes context.
	var list []actIssuerResponse
	if code := actDoAdmin(t, env, "GET", "/v1/admin/act/issuers", nil, &list); code != http.StatusOK {
		t.Fatalf("list issuers: %d", code)
	}
	var gotIss actIssuerResponse
	if code := actDo(t, h, "GET", cl.base, nil, &gotIss); code != http.StatusOK || gotIss.Context != cl.name {
		t.Fatalf("get issuer: %d %+v", code, gotIss)
	}

	// Issuance is capped at max_credits and requires idempotency_key.
	_, req, _ := act.ClientIssuanceRequest(cl.params)
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req, Credits: 1001, IdempotencyKey: "over-max"}, nil); code != http.StatusBadRequest {
		t.Fatalf("over-max issue: %d, want 400", code)
	}
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req, Credits: 10}, nil); code != http.StatusBadRequest {
		t.Fatalf("missing issue idempotency_key: %d, want 400", code)
	}

	// A retried /issue returns the same signed response. A different payload
	// with the same idempotency_key returns 409.
	pre0, req0, err := act.ClientIssuanceRequest(cl.params)
	if err != nil {
		t.Fatal(err)
	}
	var issResp1, issResp2 actIssueResponse
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req0, Credits: 1000, IdempotencyKey: "order-1"}, &issResp1); code != http.StatusOK {
		t.Fatalf("issue: %d", code)
	}
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req0, Credits: 1000, IdempotencyKey: "order-1"}, &issResp2); code != http.StatusOK || !bytes.Equal(issResp1.Response, issResp2.Response) {
		t.Fatalf("idempotent issue retry: %d equal=%v", code, bytes.Equal(issResp1.Response, issResp2.Response))
	}
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req0, Credits: 500, IdempotencyKey: "order-1"}, nil); code != http.StatusConflict {
		t.Fatalf("conflicting issue idempotency_key: %d, want 409", code)
	}
	token, err := act.ClientFinalizeIssuance(cl.params, cl.pk, pre0, req0, issResp1.Response)
	if err != nil {
		t.Fatal(err)
	}
	if cl.balance(token) != 1000 {
		t.Fatal("wrong initial balance")
	}

	// Hold 300.
	proof, prerefund, err := act.ClientProveSpend(cl.params, token, 300)
	if err != nil {
		t.Fatal(err)
	}
	idemKey := "req-1"
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: idemKey}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}
	if held.Status != actStatusHeld || held.Charge != 300 || held.HoldExpiresAt == nil {
		t.Fatalf("unexpected hold %+v", held)
	}
	localNull, err := act.ClientSpendNullifier(proof)
	if err != nil || hex.EncodeToString(localNull[:]) != held.Nullifier {
		t.Fatalf("nullifier mismatch: local=%x err=%v server=%s", localNull, err, held.Nullifier)
	}

	// Identical retry (same proof + same idempotency_key) is idempotent.
	var retry actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: idemKey}, &retry); code != http.StatusOK || retry.Nullifier != held.Nullifier {
		t.Fatalf("retry spend: %d %+v", code, retry)
	}

	// Replaying the same proof with a different idempotency_key returns 409.
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "req-2"}, nil); code != http.StatusConflict {
		t.Fatalf("replay with different idempotency_key: %d, want 409", code)
	}

	// A second proof from the same credential is a double spend.
	proof2, _, _ := act.ClientProveSpend(cl.params, token, 1)
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof2, IdempotencyKey: "req-3"}, nil); code != http.StatusConflict {
		t.Fatalf("double spend: %d, want 409", code)
	}

	refundPath := cl.base + "/spend/" + held.Nullifier + "/refund"
	cost := func(v uint64) actRefundRequest { return actRefundRequest{Cost: &v} }

	if code := actDo(t, h, "POST", refundPath, cost(301), nil); code != http.StatusBadRequest {
		t.Fatalf("cost > charge: %d, want 400", code)
	}

	// Settle at 120. The client gets 180 back, and spend_proof is cleared.
	var settled actSpendResponse
	if code := actDo(t, h, "POST", refundPath, cost(120), &settled); code != http.StatusOK {
		t.Fatalf("refund: %d", code)
	}
	if settled.Status != actStatusRefunded || *settled.Cost != 120 || len(settled.Refund) == 0 || settled.HoldExpiresAt != nil {
		t.Fatalf("unexpected settlement %+v", settled)
	}
	var proofLen sql.NullInt64
	if err := env.srv.db.QueryRow(`SELECT octet_length(spend_proof) FROM act_spends WHERE nullifier = $1`, localNull[:]).Scan(&proofLen); err != nil {
		t.Fatal(err)
	}
	if proofLen.Valid {
		t.Fatalf("spend_proof still stored after settlement (%d bytes)", proofLen.Int64)
	}

	// Same proof + same idempotency_key after settlement still works (proof_hash check).
	var retrySettled actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: idemKey}, &retrySettled); code != http.StatusOK || retrySettled.Status != actStatusRefunded {
		t.Fatalf("post-settlement retry: %d %+v", code, retrySettled)
	}

	next, err := act.ClientFinalizeRefund(cl.params, cl.pk, prerefund, proof, settled.Refund)
	if err != nil {
		t.Fatal(err)
	}
	if got := cl.balance(next); got != 880 {
		t.Fatalf("balance after refund = %d, want 880", got)
	}

	// The same cost again returns the stored refund. A different cost returns
	// 409.
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

	// Full-cost settlement (cost == charge, returned == 0) drains remaining balance cleanly.
	proof3, prerefund3, err := act.ClientProveSpend(cl.params, next, 880)
	if err != nil {
		t.Fatal(err)
	}
	var held3 actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof3, IdempotencyKey: "req-full"}, &held3); code != http.StatusOK {
		t.Fatalf("spend refunded credential: %d", code)
	}
	var settled3 actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend/"+held3.Nullifier+"/refund", cost(880), &settled3); code != http.StatusOK {
		t.Fatalf("settle at full cost: %d", code)
	}
	drained, err := act.ClientFinalizeRefund(cl.params, cl.pk, prerefund3, proof3, settled3.Refund)
	if err != nil {
		t.Fatalf("finalize zero refund: %v", err)
	}
	if got := cl.balance(drained); got != 0 {
		t.Fatalf("balance after full-cost settle = %d, want 0", got)
	}
}

func TestACTRolloverAndIssuerLifecycle(t *testing.T) {
	env := newACTTestServer(t)
	h := env.handler

	oldIss := newACTIssuer(t, env, 1000)
	newIss := newACTIssuer(t, env, 1000)

	// 1. Roll two small credentials of one issuer into one larger credential.
	// This works in production without ACT_ISSUE_TOKEN_LIST, because a
	// rollover mints no new credits.
	dustA := oldIss.credential(120)
	dustB := oldIss.credential(230)
	proofA, _, err := act.ClientProveSpend(oldIss.params, dustA, 120)
	if err != nil {
		t.Fatal(err)
	}
	proofB, _, err := act.ClientProveSpend(oldIss.params, dustB, 230)
	if err != nil {
		t.Fatal(err)
	}
	preMerged, reqMerged, err := act.ClientIssuanceRequest(oldIss.params)
	if err != nil {
		t.Fatal(err)
	}

	origTokenList := TokenList
	TokenList = []string{"origin-secret-1"}
	t.Cleanup(func() { TokenList = origTokenList })
	t.Setenv("ENV", "production")
	t.Setenv("ACT_ISSUE_TOKEN_LIST", "")
	prodH := env.buildHandler()
	originHeaders := map[string]string{"Authorization": "Bearer origin-secret-1"}
	var mergedResp actIssueResponse
	if code := actDoWithHeaders(t, prodH, "POST", oldIss.base+"/rollover", nil, originHeaders, actRolloverRequest{
		Request:        reqMerged,
		IdempotencyKey: "dust-merge-1",
		Rollover:       []actRolloverInput{{Proof: proofA}, {Proof: proofB}},
	}, &mergedResp); code != http.StatusOK {
		t.Fatalf("anonymous dust consolidation: %d, want 200", code)
	}
	if mergedResp.PurchasedCredits != 0 || mergedResp.RolledCredits != 350 || mergedResp.TotalCredits != 350 {
		t.Fatalf("unexpected merged totals: %+v", mergedResp)
	}
	mergedToken, err := act.ClientFinalizeIssuance(oldIss.params, oldIss.pk, preMerged, reqMerged, mergedResp.Response)
	if err != nil {
		t.Fatal(err)
	}
	if bal := oldIss.balance(mergedToken); bal != 350 {
		t.Fatalf("merged balance = %d, want 350", bal)
	}

	// Nullifier of rolled-over credential is recorded as rolled_over and cannot be spent, rolled over, or refunded.
	nullA, err := act.ClientSpendNullifier(proofA)
	if err != nil {
		t.Fatal(err)
	}
	nullAHex := hex.EncodeToString(nullA[:])
	var gotRoll actSpendResponse
	if code := actDoWithHeaders(t, prodH, "GET", oldIss.base+"/spend/"+nullAHex, nil, originHeaders, nil, &gotRoll); code != http.StatusOK || gotRoll.Status != actStatusRolledOver {
		t.Fatalf("get rolled-over spend: %d %+v", code, gotRoll)
	}
	if code := actDoWithHeaders(t, prodH, "POST", oldIss.base+"/spend", nil, originHeaders, actSpendRequest{Proof: proofA, IdempotencyKey: "after-roll"}, nil); code != http.StatusConflict {
		t.Fatalf("spend after rollover: %d, want 409", code)
	}
	zero := uint64(0)
	if code := actDoWithHeaders(t, prodH, "POST", oldIss.base+"/spend/"+nullAHex+"/refund", nil, originHeaders, actRefundRequest{Cost: &zero}, nil); code != http.StatusConflict {
		t.Fatalf("refund on rolled-over nullifier: %d, want 409", code)
	}

	// Re-using dust-merge-1 idempotency_key returns the identical IssuanceResponse.
	var mergedRetry actIssueResponse
	if code := actDoWithHeaders(t, prodH, "POST", oldIss.base+"/rollover", nil, originHeaders, actRolloverRequest{
		Request:        reqMerged,
		IdempotencyKey: "dust-merge-1",
		Rollover:       []actRolloverInput{{Proof: proofA}, {Proof: proofB}},
	}, &mergedRetry); code != http.StatusOK || !bytes.Equal(mergedRetry.Response, mergedResp.Response) {
		t.Fatalf("idempotent rollover retry: %d equal=%v", code, bytes.Equal(mergedRetry.Response, mergedResp.Response))
	}

	// /issue uses a separate idempotency keyspace from /rollover, so reusing "dust-merge-1" on /issue succeeds.
	t.Setenv("ACT_ISSUE_TOKEN_LIST", "mint-sep-1")
	_, sepReq, _ := act.ClientIssuanceRequest(oldIss.params)
	if code := actDoWithHeaders(t, prodH, "POST", oldIss.base+"/issue", nil, map[string]string{
		"Authorization": "Bearer mint-sep-1",
	}, actIssueRequest{Request: sepReq, Credits: 10, IdempotencyKey: "dust-merge-1"}, nil); code != http.StatusOK {
		t.Fatalf("issue with same idempotency_key as rollover: %d, want 200", code)
	}

	// 2. Cross-issuer rollover is rejected until operator allowlists oldIss on newIss.
	proofMerged, _, err := act.ClientProveSpend(oldIss.params, mergedToken, 350)
	if err != nil {
		t.Fatal(err)
	}
	preNew, reqNew, err := act.ClientIssuanceRequest(newIss.params)
	if err != nil {
		t.Fatal(err)
	}
	if code := actDoWithHeaders(t, prodH, "POST", newIss.base+"/rollover", nil, originHeaders, actRolloverRequest{
		Request:        reqNew,
		IdempotencyKey: "cross-denied",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofMerged}},
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("unlisted cross-issuer rollover: %d, want 400", code)
	}

	// 3. Operator links oldIss -> newIss, extends newIss expiry, and rejects shortening expiry.
	shorter := time.Now().UTC().Add(10 * time.Minute)
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+newIss.name, actIssuerUpdateRequest{
		ExpiresAt: &shorter,
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("shorten expires_at: %d, want 400", code)
	}
	longer := time.Now().UTC().Add(48 * time.Hour)
	var updatedNew actIssuerResponse
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+newIss.name, actIssuerUpdateRequest{
		ExpiresAt:       &longer,
		AddRolloverFrom: []string{oldIss.name},
	}, &updatedNew); code != http.StatusOK {
		t.Fatalf("update new issuer: %d", code)
	}
	if len(updatedNew.RolloverFrom) != 1 || updatedNew.RolloverFrom[0] != oldIss.name {
		t.Fatalf("unexpected rollover_from: %+v", updatedNew.RolloverFrom)
	}

	// 4. The operator sets stop_issuing_at to now on oldIss. /issue fails and
	// /spend still works.
	t.Setenv("ENV", "test")
	t.Setenv("ACT_ISSUE_TOKEN_LIST", "")
	oldSpendTok := oldIss.credential(100)
	oldTopupTok := oldIss.credential(250)
	oldRemovedTok := oldIss.credential(50)
	stopNow := time.Now().UTC().Add(-time.Second)
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+oldIss.name, actIssuerUpdateRequest{
		StopIssuingAt: &stopNow,
	}, nil); code != http.StatusOK {
		t.Fatalf("set stop_issuing_at: %d", code)
	}
	_, dummyReq, _ := act.ClientIssuanceRequest(oldIss.params)
	if code := actDo(t, h, "POST", oldIss.base+"/issue", actIssueRequest{
		Request: dummyReq, Credits: 10, IdempotencyKey: "after-stop",
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("issue after stop_issuing_at: %d, want 400", code)
	}
	spendWhileStopped, _, _ := act.ClientProveSpend(oldIss.params, oldSpendTok, 50)
	if code := actDo(t, h, "POST", oldIss.base+"/spend", actSpendRequest{
		Proof: spendWhileStopped, IdempotencyKey: "spend-after-stop",
	}, nil); code != http.StatusOK {
		t.Fatalf("spend after stop_issuing_at (before expires_at): %d, want 200", code)
	}

	// 5. After oldIss passes expires_at, a rollover onto newIss still succeeds.
	if _, err := env.srv.db.Exec(`UPDATE act_issuers SET stop_issuing_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE name = $1`, oldIss.name); err != nil {
		t.Fatal(err)
	}
	env.srv.actCache = &actIssuerCache{}

	var crossResp actIssueResponse
	if code := actDo(t, h, "POST", newIss.base+"/rollover", actRolloverRequest{
		Request:        reqNew,
		IdempotencyKey: "cross-1",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofMerged}},
	}, &crossResp); code != http.StatusOK {
		t.Fatalf("cross-issuer rollover from expired source: %d, want 200", code)
	}
	rolledTok, err := act.ClientFinalizeIssuance(newIss.params, newIss.pk, preNew, reqNew, crossResp.Response)
	if err != nil {
		t.Fatal(err)
	}
	if bal := newIss.balance(rolledTok); bal != 350 {
		t.Fatalf("cross-rolled balance = %d, want 350", bal)
	}

	// 6. Top-up + rollover on /issue (purchased + rolled = total), plus overflow check.
	proofTopup, _, err := act.ClientProveSpend(oldIss.params, oldTopupTok, 250)
	if err != nil {
		t.Fatal(err)
	}
	preTopup, reqTopup, err := act.ClientIssuanceRequest(newIss.params)
	if err != nil {
		t.Fatal(err)
	}
	// Overflow (800 + 250 > 1000) is rejected without consuming proofTopup.
	if code := actDo(t, h, "POST", newIss.base+"/issue", actIssueRequest{
		Request:        reqTopup,
		Credits:        800,
		IdempotencyKey: "topup-overflow",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofTopup}},
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("topup rollover overflow: %d, want 400", code)
	}
	// Valid top-up (600 purchased + 250 rolled = 850 total).
	var topupResp actIssueResponse
	if code := actDo(t, h, "POST", newIss.base+"/issue", actIssueRequest{
		Request:        reqTopup,
		Credits:        600,
		IdempotencyKey: "topup-ok",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofTopup}},
	}, &topupResp); code != http.StatusOK {
		t.Fatalf("topup with rollover: %d, want 200", code)
	}
	if topupResp.PurchasedCredits != 600 || topupResp.RolledCredits != 250 || topupResp.TotalCredits != 850 {
		t.Fatalf("unexpected topup totals: %+v", topupResp)
	}
	topupTok, err := act.ClientFinalizeIssuance(newIss.params, newIss.pk, preTopup, reqTopup, topupResp.Response)
	if err != nil {
		t.Fatal(err)
	}
	if bal := newIss.balance(topupTok); bal != 850 {
		t.Fatalf("topup+rollover balance = %d, want 850", bal)
	}

	// 7. The operator removes oldIss from newIss's rollover_from. A request
	// that adds and removes the same issuer is rejected. After the removal, a
	// rollover from oldIss fails.
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+newIss.name, actIssuerUpdateRequest{
		AddRolloverFrom:    []string{oldIss.name},
		RemoveRolloverFrom: []string{oldIss.name},
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("overlap add/remove rollover_from: %d, want 400", code)
	}
	var removedResp actIssuerResponse
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+newIss.name, actIssuerUpdateRequest{
		RemoveRolloverFrom: []string{oldIss.name},
	}, &removedResp); code != http.StatusOK || len(removedResp.RolloverFrom) != 0 {
		t.Fatalf("remove_rollover_from: %d %+v", code, removedResp.RolloverFrom)
	}
	proofRemoved, _, _ := act.ClientProveSpend(oldIss.params, oldRemovedTok, 50)
	_, reqRemoved, _ := act.ClientIssuanceRequest(newIss.params)
	if code := actDo(t, h, "POST", newIss.base+"/rollover", actRolloverRequest{
		Request:        reqRemoved,
		IdempotencyKey: "after-remove",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofRemoved}},
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("rollover after remove_rollover_from: %d, want 400", code)
	}

	// Idempotent retry of topup-ok still succeeds even after newIss stops issuing.
	if code := actDoAdmin(t, env, "PATCH", "/v1/admin/act/issuers/"+newIss.name, actIssuerUpdateRequest{
		StopIssuingAt: &stopNow,
	}, nil); code != http.StatusOK {
		t.Fatalf("stop newIss: %d", code)
	}
	var topupRetry actIssueResponse
	if code := actDo(t, h, "POST", newIss.base+"/issue", actIssueRequest{
		Request:        reqTopup,
		Credits:        600,
		IdempotencyKey: "topup-ok",
		Rollover:       []actRolloverInput{{Issuer: oldIss.name, Proof: proofTopup}},
	}, &topupRetry); code != http.StatusOK || !bytes.Equal(topupRetry.Response, topupResp.Response) {
		t.Fatalf("post-stop idempotent retry: %d equal=%v", code, bytes.Equal(topupRetry.Response, topupResp.Response))
	}
}

func TestACTConcurrentRolloverRaces(t *testing.T) {
	env := newACTTestServer(t)
	iss := newACTIssuer(t, env, 1000)

	// Race A: 6 goroutines roll over the same credential with different
	// idempotency keys.
	tokA := iss.credential(100)
	proofA, _, _ := act.ClientProveSpend(iss.params, tokA, 100)
	const workers = 6
	codes := make([]int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			_, req, _ := act.ClientIssuanceRequest(iss.params)
			codes[idx] = actDo(t, env.handler, "POST", iss.base+"/rollover", actRolloverRequest{
				Request:        req,
				IdempotencyKey: fmt.Sprintf("race-diff-%d", idx),
				Rollover:       []actRolloverInput{{Proof: proofA}},
			}, nil)
		}(i)
	}
	wg.Wait()
	var okCount, conflictCount int
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if okCount != 1 || conflictCount != workers-1 {
		t.Fatalf("concurrent double rollover: ok=%d conflict=%d, want 1 and %d", okCount, conflictCount, workers-1)
	}

	// Race B: 6 concurrent identical retries with the same idempotency_key all
	// get 200 and the same response.
	tokB := iss.credential(150)
	proofB, _, _ := act.ClientProveSpend(iss.params, tokB, 150)
	_, reqB, _ := act.ClientIssuanceRequest(iss.params)
	resps := make([]actIssueResponse, workers)
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			codes[idx] = actDo(t, env.handler, "POST", iss.base+"/rollover", actRolloverRequest{
				Request:        reqB,
				IdempotencyKey: "race-same-key",
				Rollover:       []actRolloverInput{{Proof: proofB}},
			}, &resps[idx])
		}(i)
	}
	wg.Wait()
	for i := range workers {
		if codes[i] != http.StatusOK {
			t.Fatalf("worker %d: status=%d, want 200", i, codes[i])
		}
		if !bytes.Equal(resps[i].Response, resps[0].Response) {
			t.Fatalf("worker %d got a different IssuanceResponse on identical retry", i)
		}
	}
}

func TestACTAuthAndValidation(t *testing.T) {
	env := newACTTestServer(t)
	h := env.handler

	// Admin issuer creation requires a valid Ed25519 signature.
	if code := actDo(t, h, "POST", "/v1/admin/act/issuers", actIssuerCreateRequest{
		Name: "unsigned", MaxCredits: 10, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, nil); code != http.StatusUnauthorized {
		t.Fatalf("unsigned admin create: %d, want 401", code)
	}

	// Invalid params (empty segment), invalid names, unknown JSON fields, trailing data.
	badCreates := []string{
		`{"name":"good-1","max_credits":10,"expires_at":"2030-01-01T00:00:00Z","params":":::"}`,
		`{"name":"good-2","max_credits":10,"expires_at":"2030-01-01T00:00:00Z","params":"brave::staging:1"}`,
		`{"name":"bad/name","max_credits":10,"expires_at":"2030-01-01T00:00:00Z"}`,
		`{"name":"..","max_credits":10,"expires_at":"2030-01-01T00:00:00Z"}`,
		`{"name":"good-3","max_credits":10,"expires_at":"2030-01-01T00:00:00Z","unknown":1}`,
		`{"name":"good-4","max_credits":10,"expires_at":"2030-01-01T00:00:00Z"}{"extra":1}`,
		`{"name":"good-5","max_credits":10,"expires_at":"2030-01-01T00:00:00Z","stop_issuing_at":"2030-01-02T00:00:00Z"}`,
		`{"name":"good-6","max_credits":10,"expires_at":"2030-01-01T00:00:00Z","rollover_from":["good-6"]}`,
	}
	for _, body := range badCreates {
		if code := actDoAdmin(t, env, "POST", "/v1/admin/act/issuers", body, nil); code != http.StatusBadRequest {
			t.Errorf("create %s: status = %d, want 400", body, code)
		}
	}

	// Replaying the exact same signed admin create request is rejected.
	reqBody := fmt.Sprintf(`{"name":"replay-%s","max_credits":10,"expires_at":"%s"}`,
		uuid.NewString(), time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	signedReq := httptest.NewRequest("POST", "/v1/admin/act/issuers", strings.NewReader(reqBody))
	if err := adminapi.SignRequest(signedReq, env.adminKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, signedReq)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first signed create: %d %s", rec1.Code, rec1.Body)
	}
	replayReq := httptest.NewRequest("POST", "/v1/admin/act/issuers", strings.NewReader(reqBody))
	replayReq.Header = signedReq.Header.Clone()
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, replayReq)
	if rec2.Code != http.StatusConflict || !strings.Contains(rec2.Body.String(), "already used") {
		t.Fatalf("replayed signed create: %d %s, want 409 already used", rec2.Code, rec2.Body)
	}

	// In production, /issue and the origin routes use separate token lists. An
	// ACT_ISSUE_TOKEN_LIST token does not need to be in TOKEN_LIST, and a
	// TOKEN_LIST token cannot call /issue.
	cl := newACTIssuer(t, env, 100)
	tok := cl.credential(20)
	spendProof, _, _ := act.ClientProveSpend(cl.params, tok, 10)
	origTokenList := TokenList
	TokenList = []string{"origin-only-token"}
	t.Cleanup(func() { TokenList = origTokenList })
	t.Setenv("ENV", "production")
	t.Setenv("ACT_ISSUE_TOKEN_LIST", "")
	prodH := env.buildHandler()
	_, issReq, _ := act.ClientIssuanceRequest(cl.params)
	if code := actDoWithHeaders(t, prodH, "POST", cl.base+"/issue", nil, map[string]string{
		"Authorization": "Bearer origin-only-token",
	}, actIssueRequest{Request: issReq, Credits: 10, IdempotencyKey: "auth-1"}, nil); code != http.StatusForbidden {
		t.Fatalf("issue in prod without ACT_ISSUE_TOKEN_LIST: %d, want 403", code)
	}
	t.Setenv("ACT_ISSUE_TOKEN_LIST", "mint-only-1,mint-only-2")
	// TOKEN_LIST token cannot mint, but can read issuer and spend.
	if code := actDoWithHeaders(t, prodH, "POST", cl.base+"/issue", nil, map[string]string{
		"Authorization": "Bearer origin-only-token",
	}, actIssueRequest{Request: issReq, Credits: 10, IdempotencyKey: "auth-2"}, nil); code != http.StatusForbidden {
		t.Fatalf("issue with TOKEN_LIST-only token: %d, want 403", code)
	}
	if code := actDoWithHeaders(t, prodH, "GET", cl.base, nil, map[string]string{
		"Authorization": "Bearer origin-only-token",
	}, nil, nil); code != http.StatusOK {
		t.Fatalf("get issuer with TOKEN_LIST token: %d, want 200", code)
	}
	// A token that is only in ACT_ISSUE_TOKEN_LIST can mint, but cannot spend
	// or read the issuer.
	if code := actDoWithHeaders(t, prodH, "POST", cl.base+"/issue", nil, map[string]string{
		"Authorization": "Bearer mint-only-2",
	}, actIssueRequest{Request: issReq, Credits: 10, IdempotencyKey: "auth-3"}, nil); code != http.StatusOK {
		t.Fatalf("issue with ACT_ISSUE_TOKEN_LIST-only token: %d, want 200", code)
	}
	if code := actDoWithHeaders(t, prodH, "POST", cl.base+"/spend", nil, map[string]string{
		"Authorization": "Bearer mint-only-2",
	}, actSpendRequest{Proof: spendProof, IdempotencyKey: "auth-spend"}, nil); code != http.StatusForbidden {
		t.Fatalf("spend with ACT_ISSUE_TOKEN_LIST-only token: %d, want 403", code)
	}
	if code := actDoWithHeaders(t, prodH, "POST", cl.base+"/spend", nil, map[string]string{
		"Authorization": "Bearer origin-only-token",
	}, actSpendRequest{Proof: spendProof, IdempotencyKey: "auth-spend-ok"}, nil); code != http.StatusOK {
		t.Fatalf("spend with TOKEN_LIST token: %d, want 200", code)
	}
}

func TestACTRejects(t *testing.T) {
	env := newACTTestServer(t)
	h := env.handler
	a := newACTIssuer(t, env, 100)
	b := newACTIssuer(t, env, 100)

	// A credential from issuer a is not valid at issuer b.
	proof, _, _ := act.ClientProveSpend(a.params, a.credential(10), 5)
	if code := actDo(t, h, "POST", b.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "k1"}, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-issuer spend: %d, want 400", code)
	}
	// Missing idempotency_key is rejected.
	if code := actDo(t, h, "POST", a.base+"/spend", actSpendRequest{Proof: proof}, nil); code != http.StatusBadRequest {
		t.Fatalf("missing idempotency_key: %d, want 400", code)
	}
	if code := actDo(t, h, "POST", a.base+"/spend", actSpendRequest{Proof: []byte("junk"), IdempotencyKey: "k2"}, nil); code != http.StatusBadRequest {
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

func TestACTConcurrentSpendReplay(t *testing.T) {
	env := newACTTestServer(t)
	cl := newACTIssuer(t, env, 100)
	token := cl.credential(100)
	proof, _, err := act.ClientProveSpend(cl.params, token, 50)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 6
	codes := make([]int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			codes[idx] = actDo(t, env.handler, "POST", cl.base+"/spend", actSpendRequest{
				Proof:          proof,
				IdempotencyKey: fmt.Sprintf("concurrent-%d", idx),
			}, nil)
		}(i)
	}
	wg.Wait()

	var okCount, conflictCount int
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("unexpected status %d in concurrent replay", code)
		}
	}
	if okCount != 1 || conflictCount != workers-1 {
		t.Fatalf("concurrent replay: ok=%d conflict=%d, want 1 and %d", okCount, conflictCount, workers-1)
	}
}

func TestACTExpiredIssuerStillSettlesAndRetries(t *testing.T) {
	env := newACTTestServer(t)
	h := env.handler
	cl := newACTIssuer(t, env, 100)
	token := cl.credential(50)
	tokenUnused := cl.credential(50)

	proof, _, _ := act.ClientProveSpend(cl.params, token, 20)
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "pre-expiry"}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}

	if _, err := env.srv.db.Exec(`UPDATE act_issuers SET expires_at = now() - interval '1 minute' WHERE name = $1`, cl.name); err != nil {
		t.Fatal(err)
	}
	env.srv.actCache = &actIssuerCache{}

	_, req, _ := act.ClientIssuanceRequest(cl.params)
	if code := actDo(t, h, "POST", cl.base+"/issue", actIssueRequest{Request: req, Credits: 1, IdempotencyKey: "exp-iss"}, nil); code != http.StatusBadRequest {
		t.Fatalf("issue after expiry: %d, want 400", code)
	}
	// Pre-expiry spend retry still succeeds after issuer expiry.
	var retry actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "pre-expiry"}, &retry); code != http.StatusOK || retry.Nullifier != held.Nullifier {
		t.Fatalf("retry pre-expiry spend after expiry: %d %+v", code, retry)
	}
	// Replay with a different idempotency_key still conflicts.
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "other"}, nil); code != http.StatusConflict {
		t.Fatalf("replay after expiry: %d, want 409", code)
	}
	// Brand-new spend after expiry is rejected.
	proofNew, _, _ := act.ClientProveSpend(cl.params, tokenUnused, 10)
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proofNew, IdempotencyKey: "post-expiry"}, nil); code != http.StatusBadRequest {
		t.Fatalf("new spend after expiry: %d, want 400", code)
	}

	zero := uint64(0)
	if code := actDo(t, h, "POST", cl.base+"/spend/"+held.Nullifier+"/refund", actRefundRequest{Cost: &zero}, nil); code != http.StatusOK {
		t.Fatalf("settle after expiry: %d, want 200", code)
	}
}

func TestACTSweepAbandonedHoldsAndPoisonPill(t *testing.T) {
	env := newACTTestServer(t)
	h := env.handler
	cl := newACTIssuer(t, env, 100)
	token := cl.credential(100)

	proof, prerefund, _ := act.ClientProveSpend(cl.params, token, 40)
	var held actSpendResponse
	if code := actDo(t, h, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "sweep-1"}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}

	// Fresh holds are left alone.
	if _, _, _, err := env.srv.sweepACTHoldsPage(context.Background(), time.Hour, 100, actSweepCursor{}); err != nil {
		t.Fatal(err)
	}
	var got actSpendResponse
	actDo(t, h, "GET", cl.base+"/spend/"+held.Nullifier, nil, &got)
	if got.Status != actStatusHeld {
		t.Fatalf("fresh hold swept: %+v", got)
	}

	// Insert two older holds with corrupt proofs ahead of the valid hold. With
	// limit=2 every hold on the first page fails, and the next page still
	// settles the valid hold.
	var issuerID uuid.UUID
	if err := env.srv.db.QueryRow(`SELECT issuer_id FROM act_issuers WHERE name = $1`, cl.name).Scan(&issuerID); err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 2; i++ {
		poisonNull := make([]byte, 32)
		poisonNull[0] = 0xd0 + i
		poisonHash := make([]byte, 32)
		if _, err := env.srv.db.Exec(`
			INSERT INTO act_spends (issuer_id, nullifier, proof_hash, idempotency_key, spend_proof, charge, created_at)
			VALUES ($1, $2, $3, $4, $5, 10, now() - interval '3 hours')`,
			issuerID, poisonNull, poisonHash, fmt.Sprintf("poison-%d", i), []byte("corrupt-proof")); err != nil {
			t.Fatal(err)
		}
		nCopy := append([]byte(nil), poisonNull...)
		t.Cleanup(func() {
			_, _ = env.srv.db.Exec(`DELETE FROM act_spends WHERE issuer_id = $1 AND nullifier = $2`, issuerID, nCopy)
		})
	}

	if _, err := env.srv.db.Exec(`UPDATE act_spends SET created_at = now() - interval '2 hours' WHERE spend_proof = $1`, proof); err != nil {
		t.Fatal(err)
	}
	// Page 1 holds only the two corrupt holds. The cursor moves to page 2,
	// which settles the valid hold.
	fetched1, settled1, cursor, err1 := env.srv.sweepACTHoldsPage(context.Background(), time.Hour, 2, actSweepCursor{})
	if err1 == nil || fetched1 != 2 || settled1 != 0 || !cursor.set {
		t.Fatalf("page 1: fetched=%d settled=%d cursor.set=%v err=%v", fetched1, settled1, cursor.set, err1)
	}
	fetched2, settled2, _, err2 := env.srv.sweepACTHoldsPage(context.Background(), time.Hour, 2, cursor)
	if err2 != nil || fetched2 < 1 || settled2 < 1 {
		t.Fatalf("page 2: fetched=%d settled=%d err=%v", fetched2, settled2, err2)
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

func TestACTConcurrentRefundAndSweep(t *testing.T) {
	env := newACTTestServer(t)
	cl := newACTIssuer(t, env, 100)
	token := cl.credential(100)
	proof, prerefund, err := act.ClientProveSpend(cl.params, token, 40)
	if err != nil {
		t.Fatal(err)
	}
	var held actSpendResponse
	if code := actDo(t, env.handler, "POST", cl.base+"/spend", actSpendRequest{Proof: proof, IdempotencyKey: "race-sweep"}, &held); code != http.StatusOK {
		t.Fatalf("spend: %d", code)
	}
	if _, err := env.srv.db.Exec(`UPDATE act_spends SET created_at = now() - interval '2 hours' WHERE spend_proof = $1`, proof); err != nil {
		t.Fatal(err)
	}

	var (
		wg         sync.WaitGroup
		refundCode int
		sweepErr   error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		c := uint64(15)
		refundCode = actDo(t, env.handler, "POST", cl.base+"/spend/"+held.Nullifier+"/refund", actRefundRequest{Cost: &c}, nil)
	}()
	go func() {
		defer wg.Done()
		_, _, _, sweepErr = env.srv.sweepACTHoldsPage(context.Background(), time.Hour, 100, actSweepCursor{})
	}()
	wg.Wait()
	if sweepErr != nil {
		t.Fatalf("sweep err: %v", sweepErr)
	}
	if refundCode != http.StatusOK && refundCode != http.StatusConflict {
		t.Fatalf("refund status = %d, want 200 or 409", refundCode)
	}

	var final actSpendResponse
	if code := actDo(t, env.handler, "GET", cl.base+"/spend/"+held.Nullifier, nil, &final); code != http.StatusOK || final.Status != actStatusRefunded {
		t.Fatalf("final spend = %d %+v, want refunded", code, final)
	}
	next, err := act.ClientFinalizeRefund(cl.params, cl.pk, prerefund, proof, final.Refund)
	if err != nil {
		t.Fatalf("finalize winning refund: %v", err)
	}
	wantBal := uint64(100) - *final.Cost
	if got := cl.balance(next); got != wantBal {
		t.Fatalf("balance = %d, want %d (cost=%d)", got, wantBal, *final.Cost)
	}
}

func TestMigrateACTSkipsWhenDBAhead(t *testing.T) {
	env := newACTTestServer(t)
	// Pretend a newer release applied ACT migration 99.
	if _, err := env.srv.db.Exec(`UPDATE act_schema_migrations SET version = 99, dirty = false`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.srv.db.Exec(`UPDATE act_schema_migrations SET version = $1, dirty = false`, actSchemaVersion)
	})
	if err := migrateACT(env.srv.db, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("migrateACT when DB ahead: %v", err)
	}
}
