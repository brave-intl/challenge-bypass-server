package server

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/closers"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/go-chi/chi"
	"github.com/pressly/lg"
)

type issuerResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

type issuerCreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int        `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type issuerFetchRequest struct {
	Cohort int `json:"cohort"`
}

func (c *Server) getLatestIssuer(issuerType string, issuerCohort int) (*Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuers(issuerType)
	if err != nil {
		if err == errIssuerNotFound {
			return nil, &handlers.AppError{
				Message: "Issuer not found",
				Code:    404,
			}
		}
		return nil, &handlers.AppError{
			Error:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}
	issuerByCohorts := breakCohorts(issuer)
	lastIssuer := &(*issuerByCohorts)[issuerCohort]
	if len(*lastIssuer) == 0 {
		return nil, &handlers.AppError{
			Message: "Cohort for this issuer not found",
			Code:    404,
		}
	}
	return &(*lastIssuer)[0], nil
}

// breaks a slice of []Issuer into a 2D slice with one slice per cohort.
// This creates an empty slice with two slices, mainly [[],[]], one per cohort.
// Then we iterate through all issuers, and position each issuer in the slice
// corresponding to their cohort. Note: this only works for two cohorts. Maybe
// we want to use a constant defining the number of cohorts?
func breakCohorts(ss *[]Issuer) (ret *[][]Issuer) {
	a := make([][]Issuer, 2)
	for _, s := range *ss {
		i := s.IssuerCohort
		a[i] = append(a[i], s)
	}
	return &a
}

func (c *Server) getIssuers(issuerType string) (*[]Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuers(issuerType)
	if err != nil {
		if err == errIssuerNotFound {
			return nil, &handlers.AppError{
				Message: "Issuer not found",
				Code:    404,
			}
		}
		return nil, &handlers.AppError{
			Error:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}
	return issuer, nil
}

func (c *Server) issuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerFetchRequest
	if err := decoder.Decode(&req); err != nil {
		return handlers.WrapError("Could not parse the request body", err)
	}

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getLatestIssuer(issuerType, req.Cohort)
		if appErr != nil {
			return appErr
		}
		expiresAt := ""
		if !issuer.ExpiresAt.IsZero() {
			expiresAt = issuer.ExpiresAt.Format(time.RFC3339)
		}
		err := json.NewEncoder(w).Encode(issuerResponse{issuer.ID, issuer.IssuerType, issuer.SigningKey.PublicKey(), expiresAt})
		if err != nil {
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerGetAllHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	issuers, appErr := c.fetchAllIssuers()
	if appErr != nil {
		return &handlers.AppError{
			Error:   appErr,
			Message: "Error getting issuers",
			Code:    500,
		}
	}
	respIssuers := []issuerResponse{}
	for _, issuer := range *issuers {
		expiresAt := ""
		if !issuer.ExpiresAt.IsZero() {
			expiresAt = issuer.ExpiresAt.Format(time.RFC3339)
		}
		respIssuers = append(respIssuers, issuerResponse{issuer.ID, issuer.IssuerType, issuer.SigningKey.PublicKey(), expiresAt})
	}

	err := json.NewEncoder(w).Encode(respIssuers)
	if err != nil {
		panic(err)
	}
	return nil
}

func (c *Server) issuerCreateHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		return handlers.WrapError("Could not parse the request body", err)
	}

	if req.ExpiresAt != nil {
		if req.ExpiresAt.Before(time.Now()) {
			return &handlers.AppError{
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	}

	if err := c.createIssuer(req.Name, req.Cohort, req.MaxTokens, req.ExpiresAt); err != nil {
		log.Errorf("%s", err)
		return &handlers.AppError{
			Error:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (c *Server) issuerRouter() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerHandler)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandler)))
	r.Method("GET", "/", middleware.InstrumentHandler("GetAllIssuers", handlers.AppHandler(c.issuerGetAllHandler)))
	return r
}
