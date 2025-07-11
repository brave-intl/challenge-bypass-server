package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
	"github.com/pressly/lg"

	"github.com/brave-intl/bat-go/libs/closers"
	"github.com/brave-intl/bat-go/libs/handlers"
	"github.com/brave-intl/bat-go/libs/middleware"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	"github.com/brave-intl/challenge-bypass-server/model"
)

type issuerResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Cohort    int16             `json:"cohort"`
}

type issuerCreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type issuerV3CreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
	ValidFrom *time.Time `json:"valid_from"`
	Duration  string     `json:"duration"` // iso 8601 duration string
	Overlap   int        `json:"overlap"`  // how many extra buffer items to create
	Buffer    int        `json:"buffer"`   // number of signing keys to have in buffer
}

type issuerFetchRequestV2 struct {
	Cohort int16 `json:"cohort"`
}

// GetLatestIssuer - get the latest issuer by type/cohort
func (c *Server) GetLatestIssuer(issuerType string, issuerCohort int16) (*model.Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuersByCohort(
		issuerType,
		issuerCohort,
		`SELECT i.*
		FROM v3_issuers i join v3_issuer_keys k on (i.issuer_id=k.issuer_id)
		WHERE i.issuer_type=$1 AND k.cohort=$2
		ORDER BY i.expires_at DESC NULLS FIRST, i.created_at DESC`,
	)
	if err != nil {
		if errors.Is(err, errIssuerCohortNotFound) {
			c.Logger.Error("Issuer with given type and cohort not found")
			return nil, &handlers.AppError{
				Message: "Issuer with given type and cohort not found",
				Code:    404,
			}
		}
		c.Logger.Error("failed to find issuer", slog.Any("err", err))
		return nil, &handlers.AppError{
			Cause:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}

	return &issuer[0], nil
}

// GetLatestIssuerKafka - get the issuer and any processing error
func (c *Server) GetLatestIssuerKafka(issuerType string, issuerCohort int16) (*model.Issuer, error) {
	issuer, err := c.fetchIssuersByCohort(
		issuerType,
		issuerCohort,
		`SELECT i.*
		FROM v3_issuers i join v3_issuer_keys k on (i.issuer_id=k.issuer_id)
		WHERE i.issuer_type like $1 || '%' AND k.cohort=$2
		ORDER BY i.expires_at DESC NULLS FIRST, i.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}

	return &issuer[0], nil
}

func (c *Server) getIssuers(ctx context.Context, issuerType string) ([]model.Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuerByType(ctx, issuerType)
	if err != nil {
		if errors.Is(err, errIssuerNotFound) {
			return nil, &handlers.AppError{
				Message: "Issuer not found",
				Code:    404,
			}
		}
		c.Logger.Error("failed to find issuer", slog.Any("err", err))
		return nil, &handlers.AppError{
			Cause:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}
	return []model.Issuer{*issuer}, nil
}

func (c *Server) issuerGetHandlerV1(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1IssuerCallTotal.WithLabelValues("getIssuer").Inc()
	defer closers.Panic(r.Context(), r.Body)

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, v1Cohort)
		if appErr != nil {
			return appErr
		}

		err := json.NewEncoder(w).Encode(makeIssuerResponse(issuer))
		if err != nil {
			c.Logger.Error("Error encoding the issuer response")
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerHandlerV3(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v3IssuerCallTotal.WithLabelValues("getIssuer").Inc()
	issuerType := chi.URLParam(r, "type")

	if issuerType == "" {
		// need an issuer type, 404 otherwise
		return &handlers.AppError{
			Message: "Issuer with given type not found",
			Code:    http.StatusNotFound,
		}
	}

	issuer, appErr := c.GetLatestIssuer(issuerType, v3Cohort)
	if appErr != nil {
		return appErr
	}

	err := json.NewEncoder(w).Encode(makeIssuerResponse(issuer))
	if err != nil {
		c.Logger.Error("Error encoding the issuer response")
		panic(err)
	}
	return nil
}

func (c *Server) issuerHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v2IssuerCallTotal.WithLabelValues("getIssuer").Inc()
	defer closers.Panic(r.Context(), r.Body)

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerFetchRequestV2
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, req.Cohort)
		if appErr != nil {
			return appErr
		}

		// get the signing public key
		err := json.NewEncoder(w).Encode(makeIssuerResponse(issuer))
		if err != nil {
			c.Logger.Error("Error encoding the issuer response")
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerGetAllHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1IssuerCallTotal.WithLabelValues("getAllIssuers").Inc()
	defer closers.Panic(r.Context(), r.Body)

	issuers, appErr := c.FetchAllIssuers()
	if appErr != nil {
		return &handlers.AppError{
			Cause:   appErr,
			Message: "Error getting issuers",
			Code:    500,
		}
	}

	respIssuers := make([]issuerResponse, len(issuers))
	for idx, currIssuer := range issuers {
		respIssuers[idx] = makeIssuerResponse(&currIssuer)
	}

	err := json.NewEncoder(w).Encode(respIssuers)
	if err != nil {
		c.Logger.Error("Error encoding issuer")
		panic(err)
	}
	return nil
}

// issuerV3CreateHandler - creation of a time aware issuer
func (c *Server) issuerV3CreateHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v3IssuerCallTotal.WithLabelValues("createIssuer").Inc()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerV3CreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if req.ExpiresAt != nil {
		if req.ExpiresAt.Before(time.Now()) {
			c.Logger.Error("Expiration time has past")
			return &handlers.AppError{
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	} else {
		// default ExpiresAt
		req.ExpiresAt = new(time.Time)
	}

	if err := c.createV3Issuer(model.Issuer{
		Version:      3,
		IssuerType:   req.Name,
		IssuerCohort: req.Cohort,
		MaxTokens:    req.MaxTokens,
		ExpiresAt:    pq.NullTime{Time: *req.ExpiresAt, Valid: req.ExpiresAt != nil},
		Buffer:       req.Buffer,
		Overlap:      req.Overlap,
		ValidFrom:    req.ValidFrom,
		Duration:     &req.Duration,
	}); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" { // unique violation
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not create new issuer",
					Code:    http.StatusConflict, // there already exists an issuer
				}
			}
		}

		return &handlers.AppError{
			Cause:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusCreated)
	return nil
}

func (c *Server) issuerCreateHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v2IssuerCallTotal.WithLabelValues("createIssuer").Inc()
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if req.ExpiresAt != nil {
		if req.ExpiresAt.Before(time.Now()) {
			c.Logger.Error("Expiration time has past")
			return &handlers.AppError{
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	}

	// set the default cohort for v1 clients
	if req.Cohort == 0 {
		req.Cohort = v1Cohort
	}

	// set expires at if nil
	if req.ExpiresAt == nil {
		req.ExpiresAt = &time.Time{}
	}

	if err := c.createIssuerV2(req.Name, req.Cohort, req.MaxTokens, req.ExpiresAt); err != nil {
		// if this is a duplicate on a constraint we already inserted it
		log.Errorf("%s", err)

		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" { // unique violation
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not create new issuer",
					Code:    http.StatusConflict, // there already exists an issuer
				}
			}
		}

		return &handlers.AppError{
			Cause:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (c *Server) issuerCreateHandlerV1(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1IssuerCallTotal.WithLabelValues("createIssuer").Inc()
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if req.ExpiresAt != nil {
		if req.ExpiresAt.Before(time.Now()) {
			c.Logger.Error("Expiration time has past")
			return &handlers.AppError{
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	}

	// set the default cohort for v1 clients
	if req.Cohort == 0 {
		req.Cohort = v1Cohort
	}

	// set expires at if nil
	if req.ExpiresAt == nil {
		req.ExpiresAt = &time.Time{}
	}

	if err := c.createIssuer(req.Name, req.Cohort, req.MaxTokens, req.ExpiresAt); err != nil {
		log.Errorf("%s", err)

		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" { // unique violation
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not create new issuer",
					Code:    http.StatusConflict, // there already exists an issuer
				}
			}
		}

		return &handlers.AppError{
			Cause:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func makeIssuerResponse(iss *model.Issuer) issuerResponse {
	expiresAt := ""
	if expt := iss.ExpiresAtTime(); !expt.IsZero() {
		expiresAt = expt.Format(time.RFC3339)
	}

	// Last key in array is the valid one
	var publicKey *crypto.PublicKey
	if len(iss.Keys) > 0 {
		publicKey = iss.Keys[len(iss.Keys)-1].CryptoSigningKey().PublicKey()
	}

	return issuerResponse{
		iss.ID.String(),
		iss.IssuerType,
		publicKey,
		expiresAt,
		iss.IssuerCohort,
	}
}

func (c *Server) issuerRouterV1() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerGetHandlerV1)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandlerV1)))
	r.Method("GET", "/", middleware.InstrumentHandler("GetAllIssuers", handlers.AppHandler(c.issuerGetAllHandler)))
	return r
}

func (c *Server) issuerRouterV2() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuerV2", handlers.AppHandler(c.issuerHandlerV2)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandlerV2)))
	return r
}

func (c *Server) issuerRouterV3() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuerV3", handlers.AppHandler(c.issuerHandlerV3)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuerV3", handlers.AppHandler(c.issuerV3CreateHandler)))
	return r
}
