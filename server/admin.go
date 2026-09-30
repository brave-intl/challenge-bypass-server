package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func (c *Server) adminRoutes(r chi.Router) {
	r.Method("GET", "/whoami", AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
		return c.adminRender(w, http.StatusOK, map[string]string{"operator": adminOperator(r, c.adminKeys)})
	}))
	r.Method("GET", "/issuers", AppHandler(c.adminListHandler))
	r.Method("POST", "/issuers", AppHandler(c.adminCreateHandler))
	r.Method("GET", "/issuers/{id}", AppHandler(c.adminGetHandler))
	r.Method("PATCH", "/issuers/{id}", AppHandler(c.adminUpdateHandler))
	r.Method("POST", "/issuers/{id}/retire", AppHandler(c.adminRetireHandler))
	r.Method("DELETE", "/issuers/{id}/retire", AppHandler(c.adminCancelRetireHandler))
	r.Method("POST", "/issuers/{id}/retire/postpone", AppHandler(c.adminPostponeHandler))
	r.Method("GET", "/audit", AppHandler(c.adminAuditHandler))
}

func (c *Server) adminRender(w http.ResponseWriter, status int, v any) *AppError {
	if err := RenderContent(v, w, status); err != nil {
		return WrapError(err, "Error encoding response", http.StatusInternalServerError)
	}
	return nil
}

// adminError maps DB-layer errors to HTTP.
func (c *Server) adminError(r *http.Request, err error) *AppError {
	var rule *adminRuleError
	var pqErr *pq.Error
	switch {
	case errors.As(err, &rule):
		return &AppError{Cause: err, Message: rule.msg, Code: http.StatusUnprocessableEntity}
	case errors.Is(err, errAdminNotFound):
		return &AppError{Cause: err, Message: "issuer not found", Code: http.StatusNotFound}
	case errors.As(err, &pqErr) && pqErr.Code == "23505":
		return &AppError{Cause: err, Message: "an issuer with that name already exists", Code: http.StatusConflict}
	}
	c.Logger.Error("admin request failed", slog.String("path", r.URL.Path), slog.Any("error", err))
	return &AppError{Cause: err, Message: "internal error", Code: http.StatusInternalServerError}
}

func adminIssuerID(r *http.Request) (uuid.UUID, *AppError) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, &AppError{Cause: err, Message: "id must be a uuid", Code: http.StatusBadRequest}
	}
	return id, nil
}

func decodeStrict(r *http.Request, v any) *AppError {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &AppError{Cause: err, Message: "invalid request body: " + err.Error(), Code: http.StatusUnprocessableEntity}
	}
	return nil
}

// respondIssuer re-reads the issuer after a mutation and renders it.
func (c *Server) respondIssuer(w http.ResponseWriter, r *http.Request, id uuid.UUID, status int) *AppError {
	c.invalidateIssuerCaches()
	iss, err := c.adminGetIssuer(r.Context(), id, time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, status, iss)
}

// invalidateIssuerCaches drops this pod's cached issuers. Other pods pick up
// changes within CACHE_DURATION_SECS.
func (c *Server) invalidateIssuerCaches() {
	if c.caches == nil {
		return
	}
	c.caches.Issuer.Clear()
	c.caches.Issuers.Clear()
	c.caches.IssuerCohort.Clear()
}

func (c *Server) logAdmin(r *http.Request, action string, id uuid.UUID) {
	c.Logger.Info("admin action", slog.String("operator", adminOperator(r, c.adminKeys)),
		slog.String("action", action), slog.String("issuer_id", id.String()))
}

func (c *Server) adminListHandler(w http.ResponseWriter, r *http.Request) *AppError {
	list, err := c.adminListIssuers(r.Context(), time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, adminapi.ListIssuersResponse{Issuers: list})
}

func (c *Server) adminGetHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	iss, err := c.adminGetIssuer(r.Context(), id, time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, iss)
}

func (c *Server) adminCreateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	var req adminapi.CreateIssuerRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	id, err := c.adminCreateIssuer(r.Context(), adminOperator(r, c.adminKeys), req)
	if err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "create", id)
	return c.respondIssuer(w, r, id, http.StatusCreated)
}

func (c *Server) adminUpdateHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.UpdateIssuerRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminUpdateIssuer(r.Context(), adminOperator(r, c.adminKeys), id, req); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "update", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminRetireHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.RetireRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminRetireIssuer(r.Context(), adminOperator(r, c.adminKeys), id, req, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "retire", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminCancelRetireHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	if err := c.adminCancelRetirement(r.Context(), adminOperator(r, c.adminKeys), id, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "cancel_retire", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminPostponeHandler(w http.ResponseWriter, r *http.Request) *AppError {
	id, appErr := adminIssuerID(r)
	if appErr != nil {
		return appErr
	}
	var req adminapi.PostponeRequest
	if appErr := decodeStrict(r, &req); appErr != nil {
		return appErr
	}
	if err := c.adminPostponeRetirement(r.Context(), adminOperator(r, c.adminKeys), id, req, time.Now()); err != nil {
		return c.adminError(r, err)
	}
	c.logAdmin(r, "postpone", id)
	return c.respondIssuer(w, r, id, http.StatusOK)
}

func (c *Server) adminAuditHandler(w http.ResponseWriter, r *http.Request) *AppError {
	var issuerID *uuid.UUID
	if s := r.URL.Query().Get("issuer_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return &AppError{Cause: err, Message: "issuer_id must be a uuid", Code: http.StatusBadRequest}
		}
		issuerID = &id
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := c.adminListAudit(r.Context(), issuerID, limit)
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, adminapi.AuditResponse{Entries: entries})
}
