package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

// Anonymous Credit Tokens (ACT): pay-per-use credits with hold-and-refund.
// Client guide: docs/act-credit-tokens.md.

const (
	// actParamsVersion pins the ACT generator derivation. Changing it (or any
	// part of the params string) invalidates every outstanding credential.
	actParamsVersion = "2026-09-30"

	actDefaultHoldTimeout = 15 * time.Minute
	actSweepBatch         = 100
)

var actCallTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cbp_api_act_total",
		Help: "ACT operations by action and outcome",
	},
	[]string{"action", "outcome"},
)

func init() {
	metrics.MustRegisterIfNotRegistered(prometheus.DefaultRegisterer, actCallTotal)
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

func actHoldTimeout() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ACT_HOLD_TIMEOUT")); err == nil && d > 0 {
		return d
	}
	return actDefaultHoldTimeout
}

// mountACTRoutes registers the ACT API. Routes are always present; without
// the "act" build tag the crypto calls fail and handlers return 501.
func (c *Server) mountACTRoutes(r chi.Router) {
	r.Method("POST", "/v1/act/issuer", AppHandler(c.actIssuerCreateHandler))
	r.Method("GET", "/v1/act/issuer/{name}", AppHandler(c.actIssuerGetHandler))
	r.Method("POST", "/v1/act/issuer/{name}/issue", AppHandler(c.actIssueHandler))
	r.Method("POST", "/v1/act/issuer/{name}/spend", AppHandler(c.actSpendHandler))
	r.Method("GET", "/v1/act/issuer/{name}/spend/{nullifier}", AppHandler(c.actSpendGetHandler))
	r.Method("POST", "/v1/act/issuer/{name}/spend/{nullifier}/refund", AppHandler(c.actRefundHandler))
}

// startACTSweeper settles abandoned holds every minute until ctx ends.
func (c *Server) startACTSweeper(ctx context.Context) {
	if !act.Available() {
		return
	}
	timeout := actHoldTimeout()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := c.SweepACTHolds(ctx, timeout, actSweepBatch)
				if err != nil {
					actCallTotal.WithLabelValues("sweep", "error").Inc()
					c.Logger.Error("act: sweep abandoned holds", slog.Any("error", err))
					continue
				}
				actCallTotal.WithLabelValues("sweep", "settled").Add(float64(n))
			}
		}
	}()
}

type actIssuerCreateRequest struct {
	Name string `json:"name"`
	// Context is bound into every credential and revealed on spend. Share it
	// across all users of the pool; never make it per-user. Defaults to Name.
	Context    string    `json:"context"`
	MaxCredits uint64    `json:"max_credits"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Params overrides the ACT domain separator
	// (organization:service:deployment:version). Leave empty for the default.
	Params string `json:"params,omitempty"`
}

type actIssuerResponse struct {
	Name       string    `json:"name"`
	Params     string    `json:"params"`
	PublicKey  []byte    `json:"public_key"`
	MaxCredits uint64    `json:"max_credits"`
	CreditBits int       `json:"credit_bits"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func makeACTIssuerResponse(iss *actIssuer) actIssuerResponse {
	return actIssuerResponse{
		Name:       iss.Name,
		Params:     iss.Params,
		PublicKey:  iss.PublicKey,
		MaxCredits: iss.MaxCredits,
		CreditBits: act.CreditBits,
		CreatedAt:  iss.CreatedAt,
		ExpiresAt:  iss.ExpiresAt,
	}
}

type actIssueRequest struct {
	Request []byte `json:"request"`
	Credits uint64 `json:"credits"`
}

type actIssueResponse struct {
	Response []byte `json:"response"`
}

type actSpendRequest struct {
	Proof []byte `json:"proof"`
}

type actRefundRequest struct {
	Cost *uint64 `json:"cost"`
}

type actSpendResponse struct {
	Nullifier string     `json:"nullifier"`
	Status    string     `json:"status"`
	Charge    uint64     `json:"charge"`
	Cost      *uint64    `json:"cost,omitempty"`
	Refund    []byte     `json:"refund,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	SettledAt *time.Time `json:"settled_at,omitempty"`
}

func makeACTSpendResponse(s *actSpend) actSpendResponse {
	return actSpendResponse{
		Nullifier: hex.EncodeToString(s.Nullifier),
		Status:    s.Status,
		Charge:    s.Charge,
		Cost:      s.Cost,
		Refund:    s.Refund,
		CreatedAt: s.CreatedAt,
		SettledAt: s.RefundedAt,
	}
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
	case errors.Is(err, errACTCostExceedsCharge):
		outcome, code, msg = "cost_exceeds_charge", http.StatusBadRequest, "Cost exceeds held charge"
	}
	actCallTotal.WithLabelValues(action, outcome).Inc()
	if code == http.StatusInternalServerError {
		c.Logger.Error("act: "+action, slog.Any("error", err))
	}
	return &AppError{Cause: err, Message: msg, Code: code}
}

func decodeACT(w http.ResponseWriter, r *http.Request, v any) *AppError {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(v); err != nil {
		return WrapError(err, "Could not parse the request body", http.StatusBadRequest)
	}
	return nil
}

func renderACT(w http.ResponseWriter, action string, status int, v any) *AppError {
	actCallTotal.WithLabelValues(action, "ok").Inc()
	if err := RenderContent(v, w, status); err != nil {
		return WrapError(err, "Error encoding response", http.StatusInternalServerError)
	}
	return nil
}

// liveACTIssuer loads the issuer named in the URL and rejects expired ones.
func (c *Server) liveACTIssuer(r *http.Request, action string) (*actIssuer, *AppError) {
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return nil, c.actError(action, err)
	}
	if iss.hasExpired(time.Now()) {
		actCallTotal.WithLabelValues(action, "expired").Inc()
		return nil, &AppError{Message: "Issuer has expired", Code: http.StatusBadRequest}
	}
	return iss, nil
}

func (c *Server) actIssuerCreateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "createIssuer"
	var req actIssuerCreateRequest
	if appErr := decodeACT(w, r, &req); appErr != nil {
		return appErr
	}
	if req.Name == "" || req.MaxCredits == 0 || req.MaxCredits > act.MaxCredits || !req.ExpiresAt.After(time.Now()) {
		return &AppError{
			Message: "name, max_credits (1..2^32-1) and a future expires_at are required",
			Code:    http.StatusBadRequest,
		}
	}
	if req.Context == "" {
		req.Context = req.Name
	}
	if req.Params == "" {
		req.Params = actDefaultParams()
	}
	if parts := strings.Split(req.Params, ":"); len(parts) != 4 {
		return &AppError{Message: "params must be organization:service:deployment:version", Code: http.StatusBadRequest}
	}

	sk, pk, err := act.GenerateKey()
	if err != nil {
		return c.actError(action, err)
	}
	iss := &actIssuer{
		Name:       req.Name,
		Params:     req.Params,
		Context:    req.Context,
		PrivateKey: sk,
		PublicKey:  pk,
		MaxCredits: req.MaxCredits,
		ExpiresAt:  req.ExpiresAt,
	}
	if err := c.createACTIssuer(r.Context(), iss); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique violation
			actCallTotal.WithLabelValues(action, "conflict").Inc()
			return &AppError{Cause: err, Message: "Issuer already exists", Code: http.StatusConflict}
		}
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusCreated, makeACTIssuerResponse(iss))
}

func (c *Server) actIssuerGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "getIssuer"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusOK, makeACTIssuerResponse(iss))
}

// actIssueHandler signs a client's issuance request. The caller (e.g. the SKU
// service) is responsible for deciding the client is entitled to `credits`.
func (c *Server) actIssueHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "issue"
	iss, appErr := c.liveACTIssuer(r, action)
	if appErr != nil {
		return appErr
	}
	var req actIssueRequest
	if appErr := decodeACT(w, r, &req); appErr != nil {
		return appErr
	}
	if req.Credits == 0 || req.Credits > iss.MaxCredits {
		actCallTotal.WithLabelValues(action, "invalid_amount").Inc()
		return &AppError{Message: "credits must be between 1 and the issuer's max_credits", Code: http.StatusBadRequest}
	}

	resp, err := act.Issue(iss.Params, iss.PrivateKey, req.Request, req.Credits, []byte(iss.Context))
	if err != nil {
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusOK, actIssueResponse{Response: resp})
}

// actSpendHandler verifies a spend proof and records its charge as a hold.
// Retrying with the identical proof returns the current state of the spend.
func (c *Server) actSpendHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "spend"
	iss, appErr := c.liveACTIssuer(r, action)
	if appErr != nil {
		return appErr
	}
	var req actSpendRequest
	if appErr := decodeACT(w, r, &req); appErr != nil {
		return appErr
	}

	info, err := act.VerifySpend(iss.Params, iss.PrivateKey, req.Proof)
	if err != nil {
		return c.actError(action, err)
	}
	wantCtx, err := act.Context([]byte(iss.Context))
	if err != nil {
		return c.actError(action, err)
	}
	if info.Context != wantCtx {
		return c.actError(action, act.ErrInvalidProof)
	}

	spend, err := c.recordACTHold(r.Context(), iss.ID, info, req.Proof)
	if err != nil {
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

func (c *Server) actSpendGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "getSpend"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	nullifier, appErr := actNullifierParam(r)
	if appErr != nil {
		return appErr
	}
	spend, err := c.fetchACTSpend(r.Context(), iss.ID, nullifier)
	if err != nil {
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

// actRefundHandler settles a hold at the actual cost and returns the refund.
// Expired issuers can still settle so in-flight holds are never stranded.
func (c *Server) actRefundHandler(w http.ResponseWriter, r *http.Request) *AppError {
	const action = "refund"
	iss, err := c.fetchACTIssuer(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		return c.actError(action, err)
	}
	nullifier, appErr := actNullifierParam(r)
	if appErr != nil {
		return appErr
	}
	var req actRefundRequest
	if appErr := decodeACT(w, r, &req); appErr != nil {
		return appErr
	}
	if req.Cost == nil {
		return &AppError{Message: "cost is required", Code: http.StatusBadRequest}
	}

	spend, err := c.finalizeACTSpend(r.Context(), iss, nullifier, *req.Cost)
	if err != nil {
		return c.actError(action, err)
	}
	return renderACT(w, action, http.StatusOK, makeACTSpendResponse(spend))
}

func actNullifierParam(r *http.Request) ([]byte, *AppError) {
	n, err := hex.DecodeString(chi.URLParam(r, "nullifier"))
	if err != nil || len(n) != 32 {
		return nil, &AppError{Message: "nullifier must be 64 hex characters", Code: http.StatusBadRequest}
	}
	return n, nil
}
