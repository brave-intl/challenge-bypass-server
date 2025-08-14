package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/google/uuid"
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
func (c *Server) BlindedTokenIssuerHandlerV2(w http.ResponseWriter, r *http.Request) *AppError {
	v2BlindedTokenCallTotal.WithLabelValues("issueTokens").Inc()
	var response blindedTokenIssueResponse
	if issuerType := URLParam(r, "type"); issuerType != "" {
		var request BlindedTokenIssueRequestV2
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Error(
				"failed to parse request body",
				slog.Any("error", err),
			)
			return WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		if request.IssuerCohort != 0 && request.IssuerCohort != 1 {
			c.Logger.Debug("Not supported Cohort")
			return &AppError{
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
			c.Logger.Error(
				"invalid issuer, must have one signing key",
				"issuerType",
				issuer.IssuerType,
			)
			return &AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}

	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

// Old endpoint, that always handles tokens with v1cohort
func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) *AppError {
	v1BlindedTokenCallTotal.WithLabelValues("issueToken").Inc()
	var response blindedTokenIssueResponse
	if issuerType := URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, v1Cohort)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenIssueRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &AppError{
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
			c.Logger.Error(
				"invalid issuer, must have one signing key",
				"issuerType",
				issuer.IssuerType,
			)
			return &AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}

	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

func (c *Server) blindedTokenRedeemHandlerV3(w http.ResponseWriter, r *http.Request) *AppError {
	v3BlindedTokenCallTotal.WithLabelValues("redeemTokens").Inc()
	ctx := r.Context()
	issuerType := URLParam(r, "type")
	if issuerType == "" {
		if err := RenderContent(blindedTokenRedeemResponse{}, w, http.StatusOK); err != nil {
			return &AppError{
				Cause:   err,
				Message: "Error encoding response",
				Code:    http.StatusInternalServerError,
			}
		}
		return nil
	}

	issuer, err := c.fetchIssuerByType(ctx, issuerType)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return &AppError{
				Message: "Issuer not found",
				Code:    http.StatusNotFound,
			}
		default:
			c.Logger.Error("error fetching issuer", slog.Any("error", err))

			return &AppError{
				Cause:   errors.New("internal server error"),
				Message: "Internal server error could not retrieve issuer",
				Code:    http.StatusInternalServerError,
			}
		}
	}

	if issuer.Version != 3 {
		return &AppError{
			Message: "Issuer must be version 3",
			Code:    http.StatusBadRequest,
		}
	}

	now := time.Now()

	if issuer.HasExpired(now) {
		return &AppError{
			Message: "Issuer has expired",
			Code:    http.StatusBadRequest,
		}
	}

	var request blindedTokenRedeemRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		c.Logger.Debug("Could not parse the request body")
		return WrapError(err, "Could not parse the request body", http.StatusBadRequest)
	}

	if request.isEmpty() {
		return &AppError{
			Message: "Empty request",
			Code:    http.StatusBadRequest,
		}
	}

	skeys, err := issuer.FindSigningKeys(now)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrInvalidIssuerType):
			return &AppError{
				Message: "Issuer must be version 3",
				Code:    http.StatusBadRequest,
			}

		case errors.Is(err, model.ErrInvalidIV3Key):
			return &AppError{
				Message: "Issuer has invalid keys for v3",
				Code:    http.StatusBadRequest,
			}

		default:
			return &AppError{
				Message: "Something went wrong",
				Code:    http.StatusBadRequest,
			}
		}
	}

	if len(skeys) == 0 {
		c.Logger.Error("failed to find appropriate key", "at", now)

		return &AppError{
			Message: "Issuer has no key that corresponds to start < now < end",
			Code:    http.StatusBadRequest,
		}
	}

	if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, skeys); err != nil {
		return &AppError{
			Message: "Could not verify that token redemption is valid",
			Code:    http.StatusBadRequest,
		}
	}

	if err := c.RedeemToken(issuer, request.TokenPreimage, request.Payload, 0); err != nil {
		c.Logger.Error("error redeeming token")
		if errors.Is(err, errDuplicateRedemption) {
			return &AppError{
				Message: err.Error(),
				Code:    http.StatusConflict,
			}
		}
		return &AppError{
			Cause:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	result := blindedTokenRedeemResponse{issuer.IssuerCohort}

	if err := RenderContent(result, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) *AppError {
	v1BlindedTokenCallTotal.WithLabelValues("redeemToken").Inc()
	var response blindedTokenRedeemResponse
	if issuerType := URLParam(r, "type"); issuerType != "" {
		issuers, appErr := c.getIssuers(r.Context(), issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return WrapError(err, "Could not parse the request body", 400)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			c.Logger.Error("Empty request")
			return &AppError{
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
				c.Logger.Error(
					"invalid issuer, must have one signing key",
					"issuerType",
					issuer.IssuerType,
				)
				return &AppError{
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
			return &AppError{
				Message: "Could not verify that token redemption is valid",
				Code:    http.StatusBadRequest,
			}
		}

		if err := c.RedeemToken(verifiedIssuer, request.TokenPreimage, request.Payload, 0); err != nil {
			if errors.Is(err, errDuplicateRedemption) {
				return &AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenRedeemResponse{verifiedCohort}
	}

	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

func (c *Server) blindedTokenBulkRedeemHandler(w http.ResponseWriter, r *http.Request) *AppError {
	v1BlindedTokenCallTotal.WithLabelValues("bulkRedeemTokens").Inc()
	var request BlindedTokenBulkRedeemRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		c.Logger.Debug("Could not parse the request body")
		return WrapError(err, "Could not parse the request body", 400)
	}

	tx, err := c.db.Begin()
	if err != nil {
		c.Logger.Debug("Could not start bulk token redemption db transaction")
		return WrapError(err, "Could not start bulk token redemption db transaction", 400)
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
			return &AppError{
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
			c.Logger.Error(
				"invalid issuer, must have one signing key",
				"issuerType",
				issuer.IssuerType,
			)
			return &AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		err := btd.VerifyTokenRedemption(token.TokenPreimage, token.Signature, request.Payload, []*crypto.SigningKey{signingKey})
		if err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			return WrapError(err, "Could not verify that token redemption is valid", 400)
		}

		if err := redeemTokenWithDB(tx, token.Issuer, token.TokenPreimage, request.Payload); err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			if err == errDuplicateRedemption {
				return &AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		c.Logger.Error(err.Error())
		return &AppError{
			Cause:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	if err := RenderContent(map[string]any{}, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) *AppError {
	v1BlindedTokenCallTotal.WithLabelValues("checkToken").Inc()
	var response any
	if issuerID := URLParam(r, "id"); issuerID != "" {
		tokenID := URLParam(r, "tokenId")
		if tokenID == "" {
			return &AppError{
				Message: errRedemptionNotFound.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		tokenID, err := url.PathUnescape(tokenID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect token ID")
			return &AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		issuer, err := c.fetchIssuer(issuerID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect issuer ID")
			return &AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		if issuer.Version == 2 {
			redemption, err := c.fetchRedemptionV2(uuid.NewSHA1(*issuer.ID, []byte(tokenID)))
			if err != nil {
				if err == errRedemptionNotFound {
					c.Logger.Debug("Redemption not found")
					return &AppError{
						Message: err.Error(),
						Code:    http.StatusBadRequest,
					}
				}
				return &AppError{
					Cause:   err,
					Message: "Could not check token redemption",
					Code:    http.StatusInternalServerError,
				}
			}

			if err := RenderContent(redemption, w, http.StatusOK); err != nil {
				return &AppError{
					Cause:   err,
					Message: "Error encoding response",
					Code:    http.StatusInternalServerError,
				}
			}
			return nil
		}

		redemption, err := c.fetchRedemption(issuer.IssuerType, tokenID)
		if err != nil {
			if err == errRedemptionNotFound {
				return &AppError{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				}
			}
			return &AppError{
				Cause:   err,
				Message: "Could not check token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = redemption
	}

	if err := RenderContent(response, w, http.StatusOK); err != nil {
		return &AppError{
			Cause:   err,
			Message: "Error encoding response",
			Code:    http.StatusInternalServerError,
		}
	}
	return nil
}
