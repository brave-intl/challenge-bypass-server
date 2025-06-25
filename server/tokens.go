package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/brave-intl/bat-go/libs/handlers"
	"github.com/brave-intl/bat-go/libs/middleware"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/model"
)

const (
	v1Cohort = int16(1)
	v3Cohort = int16(1)
)

type blindedTokenIssueRequest struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
}

// BlindedTokenIssueRequestV2 - version 2 blinded token issue request
type BlindedTokenIssueRequestV2 struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
	IssuerCohort  int16                  `json:"cohort"`
}

type blindedTokenIssueResponse struct {
	BatchProof   *crypto.BatchDLEQProof `json:"batch_proof"`
	SignedTokens []*crypto.SignedToken  `json:"signed_tokens"`
	PublicKey    *crypto.PublicKey      `json:"public_key"`
}

type blindedTokenRedeemRequest struct {
	Payload       string                        `json:"payload"`
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
}

func (r *blindedTokenRedeemRequest) isEmpty() bool {
	return r.TokenPreimage == nil || r.Signature == nil
}

type blindedTokenRedeemResponse struct {
	Cohort int16 `json:"cohort"`
}

// BlindedTokenRedemptionInfo - this is the redemption information
type BlindedTokenRedemptionInfo struct {
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
	Issuer        string                        `json:"issuer"`
}

// BlindedTokenBulkRedeemRequest - this is the redemption in bulk form
type BlindedTokenBulkRedeemRequest struct {
	Payload string                       `json:"payload"`
	Tokens  []BlindedTokenRedemptionInfo `json:"tokens"`
}

// BlindedTokenIssuerHandlerV2 - handler for token issuer v2
func (c *Server) BlindedTokenIssuerHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v2BlindedTokenCallTotal.WithLabelValues("issueTokens").Inc()
	var response blindedTokenIssueResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		var request BlindedTokenIssueRequestV2
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.WithError(err)
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		if request.IssuerCohort != 0 && request.IssuerCohort != 1 {
			c.Logger.Debug("Not supported Cohort")
			return &handlers.AppError{
				Message: "Not supported Cohort",
				Code:    http.StatusBadRequest,
			}
		}

		issuer, appErr := c.GetLatestIssuer(issuerType, request.IssuerCohort)
		if appErr != nil {
			return appErr
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].CryptoSigningKey()
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

// Old endpoint, that always handles tokens with v1cohort
func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1BlindedTokenCallTotal.WithLabelValues("issueToken").Inc()
	var response blindedTokenIssueResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, v1Cohort)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenIssueRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].CryptoSigningKey()
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) blindedTokenRedeemHandlerV3(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v3BlindedTokenCallTotal.WithLabelValues("redeemTokens").Inc()
	ctx := r.Context()

	issuerType := chi.URLParamFromCtx(ctx, "type")
	if issuerType == "" {
		return handlers.RenderContent(ctx, blindedTokenRedeemResponse{}, w, http.StatusOK)
	}

	issuer, err := c.fetchIssuerByType(ctx, issuerType)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return &handlers.AppError{
				Message: "Issuer not found",
				Code:    http.StatusNotFound,
			}
		default:
			c.Logger.WithError(err).Error("error fetching issuer")

			return &handlers.AppError{
				Cause:   errors.New("internal server error"),
				Message: "Internal server error could not retrieve issuer",
				Code:    http.StatusInternalServerError,
			}
		}
	}

	if issuer.Version != 3 {
		return &handlers.AppError{
			Message: "Issuer must be version 3",
			Code:    http.StatusBadRequest,
		}
	}

	now := time.Now()

	if issuer.HasExpired(now) {
		return &handlers.AppError{
			Message: "Issuer has expired",
			Code:    http.StatusBadRequest,
		}
	}

	var request blindedTokenRedeemRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		c.Logger.Debug("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", http.StatusBadRequest)
	}

	if request.isEmpty() {
		return &handlers.AppError{
			Message: "Empty request",
			Code:    http.StatusBadRequest,
		}
	}

	skeys, err := issuer.FindSigningKeys(now)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrInvalidIssuerType):
			return &handlers.AppError{
				Message: "Issuer must be version 3",
				Code:    http.StatusBadRequest,
			}

		case errors.Is(err, model.ErrInvalidIV3Key):
			return &handlers.AppError{
				Message: "Issuer has invalid keys for v3",
				Code:    http.StatusBadRequest,
			}

		default:
			return &handlers.AppError{
				Message: "Something went wrong",
				Code:    http.StatusBadRequest,
			}
		}
	}

	if len(skeys) == 0 {
		c.Logger.WithFields(logrus.Fields{"now": now}).Error("failed to find appropriate key")

		return &handlers.AppError{
			Message: "Issuer has no key that corresponds to start < now < end",
			Code:    http.StatusBadRequest,
		}
	}

	if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, skeys); err != nil {
		return &handlers.AppError{
			Message: "Could not verify that token redemption is valid",
			Code:    http.StatusBadRequest,
		}
	}

	if err := c.RedeemToken(issuer, request.TokenPreimage, request.Payload, 0); err != nil {
		c.Logger.Error("error redeeming token")
		if errors.Is(err, errDuplicateRedemption) {
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusConflict,
			}
		}

		return &handlers.AppError{
			Cause:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	result := blindedTokenRedeemResponse{issuer.IssuerCohort}

	return handlers.RenderContent(ctx, result, w, http.StatusOK)
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1BlindedTokenCallTotal.WithLabelValues("redeemToken").Inc()
	var response blindedTokenRedeemResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuers, appErr := c.getIssuers(r.Context(), issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			c.Logger.Error("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		var (
			verified       bool
			verifiedIssuer = &model.Issuer{}
			verifiedCohort = int16(0)
			now            = time.Now()
		)

		for _, issuer := range issuers {
			if issuer.HasExpired(now) {
				continue
			}

			// get latest signing key from issuer
			var signingKey *crypto.SigningKey
			if len(issuer.Keys) > 0 {
				signingKey = issuer.Keys[len(issuer.Keys)-1].CryptoSigningKey()
			} else {
				// need to have atleast one signing key
				c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
				return &handlers.AppError{
					Message: "Invalid Issuer",
					Code:    http.StatusBadRequest,
				}
			}

			if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, []*crypto.SigningKey{signingKey}); err != nil {
				verified = false
			} else {
				verified = true
				verifiedIssuer = &issuer
				verifiedCohort = issuer.IssuerCohort
				break
			}
		}

		if !verified {
			c.Logger.Error("Could not verify that the token redemption is valid")
			return &handlers.AppError{
				Message: "Could not verify that token redemption is valid",
				Code:    http.StatusBadRequest,
			}
		}

		if err := c.RedeemToken(verifiedIssuer, request.TokenPreimage, request.Payload, 0); err != nil {
			if errors.Is(err, errDuplicateRedemption) {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenRedeemResponse{verifiedCohort}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) blindedTokenBulkRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1BlindedTokenCallTotal.WithLabelValues("bulkRedeemTokens").Inc()
	var request BlindedTokenBulkRedeemRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		c.Logger.Debug("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	tx, err := c.db.Begin()
	if err != nil {
		c.Logger.Debug("Could not start bulk token redemption db transaction")
		return handlers.WrapError(err, "Could not start bulk token redemption db transaction", 400)
	}

	for _, token := range request.Tokens {
		// @TODO: this code seems to be from an old version - we use the `redeemTokenWithDB`, and we have no tests, so I
		// assume that is no longer used, hence the usage of v1Cohort.
		issuer, appErr := c.GetLatestIssuer(token.Issuer, v1Cohort)

		if appErr != nil {
			_ = tx.Rollback()
			c.Logger.Error(appErr.Error())
			return appErr
		}

		if token.TokenPreimage == nil || token.Signature == nil {
			_ = tx.Rollback()
			return &handlers.AppError{
				Message: "Missing preimage or signature",
				Code:    http.StatusBadRequest,
			}
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].CryptoSigningKey()
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		err := btd.VerifyTokenRedemption(token.TokenPreimage, token.Signature, request.Payload, []*crypto.SigningKey{signingKey})
		if err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			return handlers.WrapError(err, "Could not verify that token redemption is valid", 400)
		}

		if err := redeemTokenWithDB(tx, token.Issuer, token.TokenPreimage, request.Payload); err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			if err == errDuplicateRedemption {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		c.Logger.Error(err.Error())
		return &handlers.AppError{
			Cause:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	return handlers.RenderContent(r.Context(), nil, w, http.StatusOK)
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	v1BlindedTokenCallTotal.WithLabelValues("checkToken").Inc()
	var response interface{}
	if issuerID := chi.URLParam(r, "id"); issuerID != "" {
		tokenID := chi.URLParam(r, "tokenId")
		if tokenID == "" {
			return &handlers.AppError{
				Message: errRedemptionNotFound.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		tokenID, err := url.PathUnescape(tokenID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect token ID")
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		issuer, err := c.fetchIssuer(issuerID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect issuer ID")
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		if issuer.Version == 2 {
			redemption, err := c.fetchRedemptionV2(uuid.NewSHA1(*issuer.ID, []byte(tokenID)))
			if err != nil {
				if err == errRedemptionNotFound {
					c.Logger.Debug("Redemption not found")
					return &handlers.AppError{
						Message: err.Error(),
						Code:    http.StatusBadRequest,
					}
				}
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not check token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
			return handlers.RenderContent(r.Context(), redemption, w, http.StatusOK)
		}

		redemption, err := c.fetchRedemption(issuer.IssuerType, tokenID)
		if err != nil {
			if err == errRedemptionNotFound {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not check token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = redemption
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) tokenRouterV1() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.blindedTokenIssuerHandler)))
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandler)))
	r.Method(http.MethodGet, "/{id}/redemption/{tokenId}", middleware.InstrumentHandler("CheckToken", handlers.AppHandler(c.blindedTokenRedemptionHandler)))
	r.Method(http.MethodPost, "/bulk/redemption/", middleware.InstrumentHandler("BulkRedeemTokens", handlers.AppHandler(c.blindedTokenBulkRedeemHandler)))
	return r
}

// New end point to generated marked tokens
func (c *Server) tokenRouterV2() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.BlindedTokenIssuerHandlerV2)))
	return r
}

func (c *Server) tokenRouterV3() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	// for redeeming time aware issued tokens
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandlerV3)))
	return r
}
