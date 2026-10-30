package server

import (
	"context"
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
	r.Method("GET", "/whoami", AppHandler(c.adminWhoAmIHandler))
	r.Method("GET", "/issuers", AppHandler(c.adminListHandler))
	r.Method("POST", "/issuers", AppHandler(c.adminCreateHandler))
	r.Method("GET", "/issuers/{id}", AppHandler(c.adminGetHandler))
	r.Method("PATCH", "/issuers/{id}", adminMutation(c, "update", c.adminUpdateIssuer))
	r.Method("POST", "/issuers/{id}/retire", adminMutation(c, "retire",
		func(ctx context.Context, op string, id uuid.UUID, req adminapi.RetireRequest) error {
			return c.adminRetireIssuer(ctx, op, id, req, time.Now())
		}))
	r.Method("DELETE", "/issuers/{id}/retire", adminMutation(c, "cancel_retire",
		func(ctx context.Context, op string, id uuid.UUID, _ struct{}) error {
			return c.adminCancelRetirement(ctx, op, id, time.Now())
		}))
	r.Method("POST", "/issuers/{id}/retire/postpone", adminMutation(c, "postpone",
		func(ctx context.Context, op string, id uuid.UUID, req adminapi.PostponeRequest) error {
			return c.adminPostponeRetirement(ctx, op, id, req, time.Now())
		}))
	r.Method("GET", "/audit", AppHandler(c.adminAuditHandler))
}

func (c *Server) adminRender(w http.ResponseWriter, status int, v any) *AppError {
	if err := RenderContent(v, w, status); err != nil {
		return WrapError(err, "Error encoding response", http.StatusInternalServerError)
	}
	return nil
}

func (c *Server) adminError(r *http.Request, err error) *AppError {
	var rule *adminRuleError
	var pqErr *pq.Error
	switch {
	case errors.As(err, &rule):
		return &AppError{Cause: err, Message: rule.msg, Code: http.StatusUnprocessableEntity}
	case errors.Is(err, errAdminNotFound):
		return &AppError{Cause: err, Message: "issuer not found", Code: http.StatusNotFound}
	case errors.As(err, &pqErr) && pqErr.Constraint == "issuer_type_uniq":
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

// respondIssuer writes the issuer after a committed change. A failed read
// here must not look like a failed change, or the operator would retry it.
func (c *Server) respondIssuer(w http.ResponseWriter, r *http.Request, id uuid.UUID, status int) *AppError {
	iss, err := c.adminGetIssuer(r.Context(), id, time.Now())
	if err != nil {
		c.Logger.Error("admin re-read after commit failed", slog.String("path", r.URL.Path), slog.Any("error", err))
		return &AppError{Cause: err, Message: "change saved, but reading the issuer back failed; reload before retrying", Code: http.StatusInternalServerError}
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

func (c *Server) adminWhoAmIHandler(w http.ResponseWriter, r *http.Request) *AppError {
	return c.adminRender(w, http.StatusOK, adminapi.WhoAmIResponse{Operator: adminOperator(r, c.adminKeys)})
}

func (c *Server) adminListHandler(w http.ResponseWriter, r *http.Request) *AppError {
	list, err := c.adminListIssuers(r.Context(), time.Now())
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, list)
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
	c.invalidateIssuerCaches()
	return c.respondIssuer(w, r, id, http.StatusCreated)
}

// adminMutation handles a change to one issuer. It decodes a T body (none
// for struct{}), runs fn as the signing operator, logs the action and
// responds with the issuer as it now is.
func adminMutation[T any](c *Server, action string, fn func(ctx context.Context, op string, id uuid.UUID, req T) error) AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *AppError {
		id, appErr := adminIssuerID(r)
		if appErr != nil {
			return appErr
		}
		var req T
		if _, none := any(req).(struct{}); !none {
			if appErr := decodeStrict(r, &req); appErr != nil {
				return appErr
			}
		}
		if err := fn(r.Context(), adminOperator(r, c.adminKeys), id, req); err != nil {
			return c.adminError(r, err)
		}
		c.logAdmin(r, action, id)
		c.invalidateIssuerCaches()
		return c.respondIssuer(w, r, id, http.StatusOK)
	}
}

func (c *Server) adminAuditHandler(w http.ResponseWriter, r *http.Request) *AppError {
	issuerID, err := uuid.Parse(r.URL.Query().Get("issuer_id"))
	if err != nil {
		return &AppError{Cause: err, Message: "issuer_id must be a uuid", Code: http.StatusBadRequest}
	}
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if limit, err = strconv.Atoi(s); err != nil || limit < 1 || limit > 1000 {
			return &AppError{Cause: err, Message: "limit must be a number from 1 to 1000", Code: http.StatusBadRequest}
		}
	}
	entries, err := c.adminListAudit(r.Context(), issuerID, limit)
	if err != nil {
		return c.adminError(r, err)
	}
	return c.adminRender(w, http.StatusOK, entries)
}
