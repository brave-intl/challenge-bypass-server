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
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
}

type issuerCreateRequest struct {
	Name      string `json:"name"`
	MaxTokens int    `json:"max_tokens"`
	ExpiresAt string `json:"expires_at"`
}

func (c *Server) getIssuer(issuerType string) (*Issuer, *handlers.AppError) {
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
	return &(*issuer)[0], nil
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

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getIssuer(issuerType)
		if appErr != nil {
			return appErr
		}
		err := json.NewEncoder(w).Encode(issuerResponse{issuer.IssuerType, issuer.SigningKey.PublicKey()})
		if err != nil {
			panic(err)
		}
		return nil
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

	log.Errorf(req.ExpiresAt)
	var t time.Time

	if req.ExpiresAt != "" {
		layout := "2006-01-02"
		t, err := time.Parse(layout, req.ExpiresAt)
		if err != nil {
			log.Errorf("%s", err)
			return handlers.WrapError("Could not parse the request expires at", err)
		}
		if t.Before(time.Now()) {
			return &handlers.AppError{
				Error:   err,
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	}

	if err := c.createIssuer(req.Name, req.MaxTokens, t); err != nil {
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
	return r
}
