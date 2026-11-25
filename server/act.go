package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/brave-intl/challenge-bypass-server/act"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

// Anonymous Credit Tokens (ACT): pay-per-use credits with hold-and-refund.
// Client guide: docs/act-credit-tokens.md.

const (
	// actParamsVersion pins the ACT generator derivation. Changing it (or any
	// part of the params string) invalidates every outstanding credential.
	actParamsVersion = "2026-09-30"

	actDefaultHoldTimeout   = 15 * time.Minute
	actSweepBatch           = 100
	actSweepMaxBatches      = 10
	actSweepTickTimeout     = 50 * time.Second
	actMaxParamsLen         = 256
	actMaxContextLen        = 256
	actMaxIdempotencyKeyLen = 256
	actMaxRolloverProofs    = 16
)

var (
	actCallTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_act_total",
			Help: "ACT operations by action and outcome",
		},
		[]string{"action", "outcome"},
	)

	actCreditsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cbp_api_act_credits_total",
			Help: "ACT credit volume by issuer and event (issued, rolled_in, held, consumed, refunded, swept)",
		},
		[]string{"issuer", "event"},
	)
)

func init() {
	metrics.MustRegisterIfNotRegistered(prometheus.DefaultRegisterer, actCallTotal, actCreditsTotal)
}

// actEnabled reports whether ACT crypto is compiled in and enabled at runtime.
// ACT defaults to disabled so binaries built with the "act" tag stay inert in
// production until ACT_ENABLED=true is explicitly set.
func actEnabled() bool {
	return act.Available() && os.Getenv("ACT_ENABLED") == "true"
}

// actDefaultParams is the ACT domain separator for issuers created without
// explicit params: brave:challenge-bypass-server:<ENV>:<version>.
func actDefaultParams() string {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	return "brave:challenge-bypass-server:" + env + ":" + actParamsVersion
}

func actHoldTimeout(logger *slog.Logger) time.Duration {
	raw := os.Getenv("ACT_HOLD_TIMEOUT")
	if raw == "" {
		return actDefaultHoldTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		if logger != nil {
			logger.Warn("act: invalid ACT_HOLD_TIMEOUT; using default",
				slog.String("value", raw),
				slog.Duration("default", actDefaultHoldTimeout))
		}
		return actDefaultHoldTimeout
	}
	return d
}

// actIssueTokenList returns the bearer tokens allowed to mint ACT credits.
// In production this is strictly separate from TOKEN_LIST (and fails closed
// when unset) so an origin service that spends credits cannot mint them.
func actIssueTokenList() []string {
	raw := os.Getenv("ACT_ISSUE_TOKEN_LIST")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func actIssueAuthMwr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens := actIssueTokenList()
		if os.Getenv("ENV") == "production" || len(tokens) > 0 {
			token, _ := r.Context().Value(bearerTokenKey{}).(string)
			if !isSimpleTokenValid(tokens, token) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Server) actEnabledMwr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !actEnabled() {
			AppHandler(func(http.ResponseWriter, *http.Request) *AppError {
				return c.actError("disabled", act.ErrUnavailable)
			}).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mountACTRoutes registers the service-facing ACT API. Issuer creation and
// updates live under /v1/admin/act/issuers (Ed25519 operator-signed).
// /issue is authenticated solely by ACT_ISSUE_TOKEN_LIST (separate from
// TOKEN_LIST), while origin routes use SimpleTokenAuthorizedOnly in
// production. When ACT is not compiled in or ACT_ENABLED is not "true", every
// ACT route returns 501.
func (c *Server) mountACTRoutes(r chi.Router) {
	r.Route("/v1/act", func(r chi.Router) {
		r.Use(c.actEnabledMwr)
		r.With(actIssueAuthMwr).Method("POST", "/issuer/{name}/issue", AppHandler(c.actIssueHandler))
		r.Group(func(r chi.Router) {
			if os.Getenv("ENV") == "production" {
				r.Use(SimpleTokenAuthorizedOnly)
			}
			r.Method("GET", "/issuer/{name}", AppHandler(c.actIssuerGetHandler))
			r.Method("POST", "/issuer/{name}/rollover", AppHandler(c.actRolloverHandler))
			r.Method("POST", "/issuer/{name}/spend", AppHandler(c.actSpendHandler))
			r.Method("GET", "/issuer/{name}/spend/{nullifier}", AppHandler(c.actSpendGetHandler))
			r.Method("POST", "/issuer/{name}/spend/{nullifier}/refund", AppHandler(c.actRefundHandler))
		})
	})
}

// startACTSweeper settles abandoned holds every minute until ctx ends.
// Disable with ACT_SWEEPER_ENABLED=false.
func (c *Server) startACTSweeper(ctx context.Context) {
	if !actEnabled() || os.Getenv("ACT_SWEEPER_ENABLED") == "false" {
		return
	}
	timeout := actHoldTimeout(c.Logger)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.sweepACTTick(ctx, timeout)
			}
		}
	}()
}

func (c *Server) sweepACTTick(ctx context.Context, holdTimeout time.Duration) {
	tickCtx, cancel := context.WithTimeout(ctx, actSweepTickTimeout)
	defer cancel()

	var cursor actSweepCursor
	for range actSweepMaxBatches {
		fetched, settled, next, err := c.sweepACTHoldsPage(tickCtx, holdTimeout, actSweepBatch, cursor)
		if settled > 0 {
			actCallTotal.WithLabelValues("sweep", "settled").Add(float64(settled))
		}
		if err != nil {
			if c.Logger != nil {
				c.Logger.Error("act: sweep abandoned holds", slog.Any("error", err))
			}
		}
		if fetched < actSweepBatch || tickCtx.Err() != nil {
			return
		}
		cursor = next
	}
}

type actIssuerCreateRequest struct {
	Name string `json:"name"`
	// Context is bound into every credential and revealed on spend. Share it
	// across all users of the pool; never make it per-user. Defaults to Name.
	Context       string     `json:"context"`
	MaxCredits    uint64     `json:"max_credits"`
	StopIssuingAt *time.Time `json:"stop_issuing_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	// Params overrides the ACT domain separator
	// (organization:service:deployment:version). Leave empty for the default.
	Params string `json:"params,omitempty"`
	// RolloverFrom lists existing ACT issuer names whose unspent credentials
	// may be rolled into this issuer. Same-issuer dust consolidation is always
	// allowed without listing the issuer itself.
	RolloverFrom []string `json:"rollover_from,omitempty"`
}

type actIssuerUpdateRequest struct {
	StopIssuingAt      *time.Time `json:"stop_issuing_at,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	AddRolloverFrom    []string   `json:"add_rollover_from,omitempty"`
	RemoveRolloverFrom []string   `json:"remove_rollover_from,omitempty"`
}

type actIssuerResponse struct {
	Name          string     `json:"name"`
	Params        string     `json:"params"`
	Context       string     `json:"context"`
	PublicKey     []byte     `json:"public_key"`
	MaxCredits    uint64     `json:"max_credits"`
	CreditBits    int        `json:"credit_bits"`
	CreatedAt     time.Time  `json:"created_at"`
	StopIssuingAt *time.Time `json:"stop_issuing_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RolloverFrom  []string   `json:"rollover_from,omitempty"`
}

func makeACTIssuerResponse(iss *actIssuer) actIssuerResponse {
	return actIssuerResponse{
		Name:          iss.Name,
		Params:        iss.Params,
		Context:       iss.Context,
		PublicKey:     iss.PublicKey,
		MaxCredits:    iss.MaxCredits,
		CreditBits:    act.CreditBits,
		CreatedAt:     iss.CreatedAt,
		StopIssuingAt: iss.StopIssuingAt,
		ExpiresAt:     iss.ExpiresAt,
		RolloverFrom:  iss.RolloverFrom,
	}
}

type actRolloverInput struct {
	// Issuer is the source issuer name for Proof. Defaults to the target issuer
	// name when omitted (for same-issuer dust consolidation).
	Issuer string `json:"issuer,omitempty"`
	Proof  []byte `json:"proof"`
}

type actIssueRequest struct {
	Request        []byte             `json:"request"`
	Credits        uint64             `json:"credits"`
	IdempotencyKey string             `json:"idempotency_key"`
	Rollover       []actRolloverInput `json:"rollover,omitempty"`
}

type actRolloverRequest struct {
	Request        []byte             `json:"request"`
	IdempotencyKey string             `json:"idempotency_key"`
	Rollover       []actRolloverInput `json:"rollover"`
}

type actIssueResponse struct {
	Response         []byte `json:"response"`
	PurchasedCredits uint64 `json:"purchased_credits"`
	RolledCredits    uint64 `json:"rolled_credits"`
	TotalCredits     uint64 `json:"total_credits"`
}

func makeACTIssueResponse(ins *actIssuance) actIssueResponse {
	return actIssueResponse{
		Response:         ins.Response,
		PurchasedCredits: ins.PurchasedCredits,
		RolledCredits:    ins.RolledCredits,
		TotalCredits:     ins.TotalCredits,
	}
}

type actSpendRequest struct {
	Proof          []byte `json:"proof"`
	IdempotencyKey string `json:"idempotency_key"`
}

type actRefundRequest struct {
	Cost *uint64 `json:"cost"`
}

type actSpendResponse struct {
	Nullifier     string     `json:"nullifier"`
	Status        string     `json:"status"`
	Charge        uint64     `json:"charge"`
	Cost          *uint64    `json:"cost,omitempty"`
	Refund        []byte     `json:"refund,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	HoldExpiresAt *time.Time `json:"hold_expires_at,omitempty"`
	SettledAt     *time.Time `json:"settled_at,omitempty"`
}

func makeACTSpendResponse(s *actSpend) actSpendResponse {
	resp := actSpendResponse{
		Nullifier: hex.EncodeToString(s.Nullifier),
		Status:    s.Status,
		Charge:    s.Charge,
		Cost:      s.Cost,
		Refund:    s.Refund,
		CreatedAt: s.CreatedAt,
		SettledAt: s.RefundedAt,
	}
	if s.Status == actStatusHeld {
		exp := s.CreatedAt.Add(actHoldTimeout(nil))
		resp.HoldExpiresAt = &exp
	}
	return resp
}

// actError maps ACT and storage errors to HTTP errors and counts the outcome.
func (c *Server) actError(action string, err error) *AppError {
	outcome, code, msg := "error", http.StatusInternalServerError, "Internal server error"
	switch {
	case errors.Is(err, act.ErrUnavailable):
		outcome, code, msg = "unavailable", http.StatusNotImplemented, "ACT is not enabled on this server"
	case errors.Is(err, act.ErrInvalidProof):
		outcome, code, msg = "invalid_proof", http.StatusBadRequest, "Invalid proof"
	case errors.Is(err, act.ErrMalformed):
		outcome, code, msg = "malformed", http.StatusBadRequest, "Malformed ACT message"
	case errors.Is(err, act.ErrInvalidAmount):
		outcome, code, msg = "invalid_amount", http.StatusBadRequest, "Invalid credit amount"
	case errors.Is(err, errACTIssuerNotFound):
		outcome, code, msg = "issuer_not_found", http.StatusNotFound, "Issuer not found"
	case errors.Is(err, errACTSpendNotFound):
		outcome, code, msg = "spend_not_found", http.StatusNotFound, "Spend not found"
	case errors.Is(err, errACTDoubleSpend):
		outcome, code, msg = "double_spend", http.StatusConflict, "Credential already spent"
	case errors.Is(err, errACTRefundConflict):
		outcome, code, msg = "refund_conflict", http.StatusConflict, "Spend already settled with a different cost"
	case errors.Is(err, errACTIssuanceConflict):
		outcome, code, msg = "issuance_conflict", http.StatusConflict, "Idempotency key already used with a different issuance request"
	case errors.Is(err, errACTCostExceedsCharge):
		outcome, code, msg = "cost_exceeds_charge", http.StatusBadRequest, "Cost exceeds held charge"
	case errors.Is(err, errACTRolloverNotAllowed):
		outcome, code, msg = "rollover_not_allowed", http.StatusBadRequest, "Rollover from that source issuer is not allowed"
	case errors.Is(err, errACTIssuanceStopped):
		outcome, code, msg = "issuance_stopped", http.StatusBadRequest, "Issuer is no longer accepting new issuances"
	case errors.Is(err, errACTInvalidUpdate):
		outcome, code, msg = "bad_request", http.StatusBadRequest, err.Error()
	}
	actCallTotal.WithLabelValues(action, outcome).Inc()
	if code == http.StatusInternalServerError && c.Logger != nil {
		c.Logger.Error("act: "+action, slog.Any("error", err))
	}
	return &AppError{Cause: err, Message: msg, Code: code}
}

func decodeACT(w http.ResponseWriter, r *http.Request, action string, v any) *AppError {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return WrapError(err, "Could not parse the request body", http.StatusBadRequest)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "Could not parse the request body: trailing data", Code: http.StatusBadRequest}
	}
	return nil
}

func (c *Server) renderACT(w http.ResponseWriter, action string, status int, v any) *AppError {
	if err := RenderContent(v, w, status); err != nil {
		actCallTotal.WithLabelValues(action, "error").Inc()
		if c.Logger != nil {
			c.Logger.Error("act: encode response", slog.String("action", action), slog.Any("error", err))
		}
		return WrapError(err, "Error encoding response", http.StatusInternalServerError)
	}
	actCallTotal.WithLabelValues(action, "ok").Inc()
	return nil
}

func validateACTParams(params string) bool {
	if len(params) == 0 || len(params) > actMaxParamsLen || !utf8.ValidString(params) {
		return false
	}
	parts := strings.Split(params, ":")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

func validateACTIssuerName(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	return adminNamePattern.MatchString(name)
}

func validateACTIdempotencyKey(key string) bool {
	return len(key) > 0 && len(key) <= actMaxIdempotencyKeyLen && utf8.ValidString(key)
}

func hashACTIssuanceRequest(targetName string, purchased uint64, reqBytes []byte, rollovers []actRolloverInput) [32]byte {
	h := sha256.New()
	writeLenBytes := func(b []byte) {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(b)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(b)
	}
	writeLenBytes([]byte("act-issuance-v1"))
	writeLenBytes([]byte(targetName))
	var creditBuf [8]byte
	binary.LittleEndian.PutUint64(creditBuf[:], purchased)
	_, _ = h.Write(creditBuf[:])
	writeLenBytes(reqBytes)
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], uint64(len(rollovers)))
	_, _ = h.Write(countBuf[:])
	for _, r := range rollovers {
		src := r.Issuer
		if src == "" {
			src = targetName
		}
		writeLenBytes([]byte(src))
		writeLenBytes(r.Proof)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

func (c *Server) actAdminIssuerListHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "listIssuers"
	if !actEnabled() {
		return c.actError(action, act.ErrUnavailable)
	}
	issuers, err := c.listACTIssuers(r.Context())
	if err != nil {
		return c.actError(action, err)
	}
	out := make([]actIssuerResponse, 0, len(issuers))
	for i := range issuers {
		out = append(out, makeACTIssuerResponse(&issuers[i]))
	}
	return c.renderACT(w, action, http.StatusOK, out)
}

func (c *Server) actAdminIssuerCreateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "createIssuer"
	if !actEnabled() {
		return c.actError(action, act.ErrUnavailable)
	}
	var req actIssuerCreateRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if !validateACTIssuerName(req.Name) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{
			Message: "name must be 1..64 characters matching [A-Za-z0-9._-] and not '.' or '..'",
			Code:    http.StatusBadRequest,
		}
	}
	now := time.Now()
	if req.MaxCredits == 0 || req.MaxCredits > act.MaxCredits || !req.ExpiresAt.After(now) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{
			Message: "max_credits (1..2^32-1) and a future expires_at are required",
			Code:    http.StatusBadRequest,
		}
	}
	if req.StopIssuingAt != nil && (!req.StopIssuingAt.After(now) || req.StopIssuingAt.After(req.ExpiresAt)) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{
			Message: "stop_issuing_at must be in the future and at or before expires_at",
			Code:    http.StatusBadRequest,
		}
	}
	if err := rejectFarTimes(now, &req.ExpiresAt, req.StopIssuingAt); err != nil {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Cause: err, Message: err.Error(), Code: http.StatusBadRequest}
	}
	if req.Context == "" {
		req.Context = req.Name
	}
	if len(req.Context) > actMaxContextLen || !utf8.ValidString(req.Context) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "context must be valid UTF-8 up to 256 bytes", Code: http.StatusBadRequest}
	}
	if req.Params == "" {
		req.Params = actDefaultParams()
	}
	if !validateACTParams(req.Params) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "params must be four non-empty ':'-separated fields (organization:service:deployment:version) up to 256 bytes", Code: http.StatusBadRequest}
	}

	rolloverFrom := dedupeStrings(req.RolloverFrom)
	for _, src := range rolloverFrom {
		if src == req.Name {
			actCallTotal.WithLabelValues(action, "bad_request").Inc()
			return &AppError{Message: "rollover_from must not list the issuer itself (same-issuer consolidation is always allowed)", Code: http.StatusBadRequest}
		}
		if !validateACTIssuerName(src) {
			actCallTotal.WithLabelValues(action, "bad_request").Inc()
			return &AppError{Message: "invalid issuer name in rollover_from", Code: http.StatusBadRequest}
		}
	}

	sk, pk, err := act.GenerateKey()
	if err != nil {
		return c.actError(action, err)
	}
	iss := &actIssuer{
		Name:          req.Name,
		Params:        req.Params,
		Context:       req.Context,
		PrivateKey:    sk,
		PublicKey:     pk,
		MaxCredits:    req.MaxCredits,
		StopIssuingAt: utcTime(req.StopIssuingAt),
		ExpiresAt:     req.ExpiresAt.UTC(),
	}
	var operator string
	if c.adminKeys != nil {
		operator = adminOperator(r, c.adminKeys)
	}
	if err := c.createACTIssuer(r.Context(), operator, iss, rolloverFrom, req); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			actCallTotal.WithLabelValues(action, "conflict").Inc()
			if pqErr.Constraint == "issuer_admin_audit_signature_uniq" {
				return &AppError{Cause: err, Message: "this signed request was already used; sign a new one", Code: http.StatusConflict}
			}
			return &AppError{Cause: err, Message: "Issuer already exists", Code: http.StatusConflict}
		}
		return c.actError(action, err)
	}
	return c.renderACT(w, action, http.StatusCreated, makeACTIssuerResponse(iss))
}

func (c *Server) actAdminIssuerUpdateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "updateIssuer"
	if !actEnabled() {
		return c.actError(action, act.ErrUnavailable)
	}
	name := chi.URLParam(r, "name")
	var req actIssuerUpdateRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if req.StopIssuingAt == nil && req.ExpiresAt == nil && len(req.AddRolloverFrom) == 0 && len(req.RemoveRolloverFrom) == 0 {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "at least one of stop_issuing_at, expires_at, add_rollover_from, or remove_rollover_from is required", Code: http.StatusBadRequest}
	}
	now := time.Now()
	if err := rejectFarTimes(now, req.StopIssuingAt, req.ExpiresAt); err != nil {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Cause: err, Message: err.Error(), Code: http.StatusBadRequest}
	}
	addSources := dedupeStrings(req.AddRolloverFrom)
	addSet := make(map[string]struct{}, len(addSources))
	for _, src := range addSources {
		if !validateACTIssuerName(src) {
			actCallTotal.WithLabelValues(action, "bad_request").Inc()
			return &AppError{Message: "invalid issuer name in add_rollover_from", Code: http.StatusBadRequest}
		}
		addSet[src] = struct{}{}
	}
	removeSources := dedupeStrings(req.RemoveRolloverFrom)
	for _, src := range removeSources {
		if !validateACTIssuerName(src) {
			actCallTotal.WithLabelValues(action, "bad_request").Inc()
			return &AppError{Message: "invalid issuer name in remove_rollover_from", Code: http.StatusBadRequest}
		}
		if _, both := addSet[src]; both {
			actCallTotal.WithLabelValues(action, "bad_request").Inc()
			return &AppError{Message: "issuer cannot appear in both add_rollover_from and remove_rollover_from", Code: http.StatusBadRequest}
		}
	}

	var operator string
	if c.adminKeys != nil {
		operator = adminOperator(r, c.adminKeys)
	}
	iss, err := c.updateACTIssuer(r.Context(), operator, name, req.StopIssuingAt, req.ExpiresAt, addSources, removeSources, req)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "issuer_admin_audit_signature_uniq" {
			actCallTotal.WithLabelValues(action, "conflict").Inc()
			return &AppError{Cause: err, Message: "this signed request was already used; sign a new one", Code: http.StatusConflict}
		}
		return c.actError(action, err)
	}
	return c.renderACT(w, action, http.StatusOK, makeACTIssuerResponse(iss))
}

func (c *Server) actIssuerGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "getIssuer"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	return c.renderACT(w, action, http.StatusOK, makeACTIssuerResponse(iss))
}

// actIssueHandler signs a client's issuance request for `credits` newly
// purchased credits plus any optional unspent balances rolled over from allowed
// source issuers. Retrying with the same idempotency_key and request returns
// the stored IssuanceResponse.
func (c *Server) actIssueHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "issue"
	var req actIssueRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if req.Credits == 0 {
		actCallTotal.WithLabelValues(action, "invalid_amount").Inc()
		return &AppError{Message: "credits must be at least 1 (use /rollover for zero-purchase balance rollovers)", Code: http.StatusBadRequest}
	}
	return c.handleACTIssuance(w, r, action, req.IdempotencyKey, req.Request, req.Credits, req.Rollover)
}

// actRolloverHandler performs a standalone anonymous balance rollover or dust
// consolidation (purchased_credits = 0). Every credit issued on the target
// issuer is backed 1:1 by verified, newly nullified spend proofs from the
// target issuer itself or an operator-allowed source issuer.
func (c *Server) actRolloverHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "rollover"
	var req actRolloverRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if len(req.Rollover) == 0 {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "at least one rollover proof is required", Code: http.StatusBadRequest}
	}
	return c.handleACTIssuance(w, r, action, req.IdempotencyKey, req.Request, 0, req.Rollover)
}

func (c *Server) handleACTIssuance(
	w http.ResponseWriter,
	r *http.Request,
	action string,
	idempotencyKey string,
	issuanceReq []byte,
	purchasedCredits uint64,
	rolloverInputs []actRolloverInput,
) *AppError {
	if !validateACTIdempotencyKey(idempotencyKey) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "idempotency_key is required (valid UTF-8, 1..256 bytes)", Code: http.StatusBadRequest}
	}
	if len(rolloverInputs) > actMaxRolloverProofs {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "at most 16 rollover proofs are allowed per request", Code: http.StatusBadRequest}
	}

	ctx := r.Context()
	target, err := c.fetchACTIssuer(ctx, chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}

	// Scope idempotency keys by action ("issue:" vs "rollover:") so an
	// anonymous /rollover call cannot collide with a billing /issue key.
	scopedKey := action + ":" + idempotencyKey
	reqHash := hashACTIssuanceRequest(target.Name, purchasedCredits, issuanceReq, rolloverInputs)

	// Fast-path idempotent retry: return the stored response even if the
	// target issuer has since passed stop_issuing_at or expires_at.
	existing, err := c.fetchACTIssuance(ctx, target.ID, scopedKey)
	if err != nil {
		return c.actError(action, err)
	}
	if existing != nil {
		if !bytes.Equal(existing.RequestHash, reqHash[:]) {
			return c.actError(action, errACTIssuanceConflict)
		}
		return c.renderACT(w, action, http.StatusOK, makeACTIssueResponse(existing))
	}

	if !target.canIssue(time.Now()) {
		return c.actError(action, errACTIssuanceStopped)
	}

	type nullifierKey struct {
		issuerID  uuid.UUID
		nullifier [32]byte
	}
	seenNullifiers := make(map[nullifierKey]struct{}, len(rolloverInputs))
	verified := make([]verifiedRolloverProof, 0, len(rolloverInputs))
	var rolledCredits uint64

	for _, item := range rolloverInputs {
		src := target
		if item.Issuer != "" && item.Issuer != target.Name {
			src, err = c.fetchACTIssuer(ctx, item.Issuer)
			if err != nil {
				return c.actError(action, err)
			}
		}
		if !target.allowsRolloverFrom(src.ID) {
			return c.actError(action, errACTRolloverNotAllowed)
		}
		info, err := act.VerifySpend(src.Params, src.PrivateKey, item.Proof)
		if err != nil {
			return c.actError(action, err)
		}
		if info.Charge == 0 {
			return c.actError(action, act.ErrInvalidAmount)
		}
		if info.Context != src.ContextScalar {
			return c.actError(action, act.ErrInvalidProof)
		}
		nk := nullifierKey{issuerID: src.ID, nullifier: info.Nullifier}
		if _, dup := seenNullifiers[nk]; dup {
			return c.actError(action, errACTDoubleSpend)
		}
		seenNullifiers[nk] = struct{}{}

		if info.Charge > target.MaxCredits || rolledCredits > target.MaxCredits-info.Charge {
			actCallTotal.WithLabelValues(action, "invalid_amount").Inc()
			return &AppError{Message: "total credits (purchased + rolled over) exceeds issuer max_credits", Code: http.StatusBadRequest}
		}
		rolledCredits += info.Charge
		verified = append(verified, verifiedRolloverProof{
			SourceID:  src.ID,
			Nullifier: info.Nullifier,
			ProofHash: sha256.Sum256(item.Proof),
			Charge:    info.Charge,
		})
	}

	if purchasedCredits > target.MaxCredits || rolledCredits > target.MaxCredits-purchasedCredits {
		actCallTotal.WithLabelValues(action, "invalid_amount").Inc()
		return &AppError{Message: "total credits (purchased + rolled over) exceeds issuer max_credits", Code: http.StatusBadRequest}
	}
	totalCredits := purchasedCredits + rolledCredits
	if totalCredits == 0 || totalCredits > act.MaxCredits {
		actCallTotal.WithLabelValues(action, "invalid_amount").Inc()
		return &AppError{Message: "total credits must be between 1 and the issuer's max_credits", Code: http.StatusBadRequest}
	}

	issuance, created, err := c.executeACTIssuance(
		ctx, target, scopedKey, reqHash[:], issuanceReq, purchasedCredits, rolledCredits, verified,
	)
	if err != nil {
		return c.actError(action, err)
	}
	if created {
		if issuance.PurchasedCredits > 0 {
			actCreditsTotal.WithLabelValues(target.Name, "issued").Add(float64(issuance.PurchasedCredits))
		}
		if issuance.RolledCredits > 0 {
			actCreditsTotal.WithLabelValues(target.Name, "rolled_in").Add(float64(issuance.RolledCredits))
		}
	}
	return c.renderACT(w, action, http.StatusOK, makeACTIssueResponse(issuance))
}

// actSpendHandler verifies a spend proof and records its charge as a hold.
// Retrying with the identical proof and idempotency_key returns the current
// state of the spend, even if the issuer has since expired. Replaying the same
// proof with a different idempotency_key is rejected with 409.
func (c *Server) actSpendHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "spend"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	var req actSpendRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if !validateACTIdempotencyKey(req.IdempotencyKey) {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "idempotency_key is required (valid UTF-8, 1..256 bytes)", Code: http.StatusBadRequest}
	}

	info, err := act.VerifySpend(iss.Params, iss.PrivateKey, req.Proof)
	if err != nil {
		return c.actError(action, err)
	}
	if info.Charge == 0 {
		return c.actError(action, act.ErrInvalidAmount)
	}
	if info.Context != iss.ContextScalar {
		return c.actError(action, act.ErrInvalidProof)
	}

	proofHash := sha256.Sum256(req.Proof)
	if iss.hasExpired(time.Now()) {
		existing, err := c.fetchACTSpend(r.Context(), iss.ID, info.Nullifier[:])
		if err == nil {
			if !bytes.Equal(existing.ProofHash, proofHash[:]) || existing.IdempotencyKey != req.IdempotencyKey {
				return c.actError(action, errACTDoubleSpend)
			}
			return c.renderACT(w, action, http.StatusOK, makeACTSpendResponse(existing))
		}
		if !errors.Is(err, errACTSpendNotFound) {
			return c.actError(action, err)
		}
		actCallTotal.WithLabelValues(action, "expired").Inc()
		return &AppError{Message: "Issuer has expired", Code: http.StatusBadRequest}
	}

	spend, created, err := c.recordACTHold(r.Context(), iss.ID, info, req.Proof, proofHash[:], req.IdempotencyKey)
	if err != nil {
		return c.actError(action, err)
	}
	if created {
		actCreditsTotal.WithLabelValues(iss.Name, "held").Add(float64(spend.Charge))
	}
	return c.renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

func (c *Server) actSpendGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "getSpend"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	nullifier, appErr := actNullifierParam(r, action)
	if appErr != nil {
		return appErr
	}
	spend, err := c.fetchACTSpend(r.Context(), iss.ID, nullifier)
	if err != nil {
		return c.actError(action, err)
	}
	return c.renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

// actRefundHandler settles a hold at the actual cost and returns the refund.
// Expired issuers can still settle so in-flight holds are never stranded.
func (c *Server) actRefundHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "refund"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	nullifier, appErr := actNullifierParam(r, action)
	if appErr != nil {
		return appErr
	}
	var req actRefundRequest
	if appErr := decodeACT(w, r, action, &req); appErr != nil {
		return appErr
	}
	if req.Cost == nil {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return &AppError{Message: "cost is required", Code: http.StatusBadRequest}
	}

	spend, settledNow, err := c.finalizeACTSpend(r.Context(), iss, nullifier, *req.Cost)
	if err != nil {
		return c.actError(action, err)
	}
	if settledNow {
		actCreditsTotal.WithLabelValues(iss.Name, "consumed").Add(float64(*req.Cost))
		actCreditsTotal.WithLabelValues(iss.Name, "refunded").Add(float64(spend.Charge - *req.Cost))
	}
	return c.renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

func actNullifierParam(r *http.Request, action string) ([]byte, *AppError) {
	n, err := hex.DecodeString(chi.URLParam(r, "nullifier"))
	if err != nil || len(n) != 32 {
		actCallTotal.WithLabelValues(action, "bad_request").Inc()
		return nil, &AppError{Message: "nullifier must be 64 hex characters", Code: http.StatusBadRequest}
	}
	return n, nil
}
