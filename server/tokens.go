package server

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/go-chi/chi"
)

type BlindedTokenIssueRequest struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
}

type BlindedTokenIssueResponse struct {
	BatchProof   *crypto.BatchDLEQProof `json:"batch_proof"`
	SignedTokens []*crypto.SignedToken  `json:"signed_tokens"`
}

type BlindedTokenRedeemRequest struct {
	Payload       string                        `json:"payload"`
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
}

type BlindedTokenRedemptionInfo struct {
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
	Issuer        string                        `json:"issuer"`
}

type BlindedTokenBulkRedeemRequest struct {
	Payload string                       `json:"payload"`
	Tokens  []BlindedTokenRedemptionInfo `json:"tokens"`
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getIssuer(issuerType)
		if appErr != nil {
			return appErr
		}

		var request BlindedTokenIssueRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			return handlers.WrapError("Could not parse the request body", err)
		}

		if request.BlindedTokens == nil {
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, issuer.SigningKey)
		if err != nil {
			return &handlers.AppError{
				Error:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}

		err = json.NewEncoder(w).Encode(BlindedTokenIssueResponse{proof, signedTokens})
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getIssuer(issuerType)
		if appErr != nil {
			return appErr
		}

		var request BlindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			return handlers.WrapError("Could not parse the request body", err)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, []*crypto.SigningKey{issuer.SigningKey}); err != nil {
			return handlers.WrapError("Could not verify that token redemption is valid", err)
		}

		if err := c.redeemToken(issuerType, request.TokenPreimage, request.Payload); err != nil {
			if err == DuplicateRedemptionError {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			} else {
				return &handlers.AppError{
					Error:   err,
					Message: "Could not mark token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
		}
	}
	return nil
}

func (c *Server) blindedTokenBulkRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {

	var request BlindedTokenBulkRedeemRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		return handlers.WrapError("Could not parse the request body", err)
	}

	tx, err := c.db.Begin()
	if err != nil {
		return handlers.WrapError("Could not start bulk token redemption db transaction", err)
	}

	for _, token := range request.Tokens {
		issuer, appErr := c.getIssuer(token.Issuer)
		if appErr != nil {
			_ = tx.Rollback()
			return appErr
		}

		if token.TokenPreimage == nil || token.Signature == nil {
			_ = tx.Rollback()
			return &handlers.AppError{
				Message: "Missing preimage or signature",
				Code:    http.StatusBadRequest,
			}
		}

		if err := btd.VerifyTokenRedemption(token.TokenPreimage, token.Signature, request.Payload, []*crypto.SigningKey{issuer.SigningKey}); err != nil {
			_ = tx.Rollback()
			return handlers.WrapError("Could not verify that token redemption is valid", err)
		}

		if err := redeemTokenWithDB(tx, token.Issuer, token.TokenPreimage, request.Payload); err != nil {
			_ = tx.Rollback()
			if err == DuplicateRedemptionError {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			} else {
				return &handlers.AppError{
					Error:   err,
					Message: "Could not mark token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return &handlers.AppError{
			Error:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	return nil
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		tokenId := r.FormValue("tokenId")
		redemption, err := c.fetchRedemption(issuerType, tokenId)
		if err != nil {
			if err == RedemptionNotFoundError {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				}
			} else {
				return &handlers.AppError{
					Error:   err,
					Message: "Could not check token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
		}

		err = json.NewEncoder(w).Encode(redemption)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (c *Server) tokenRouter() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.blindedTokenIssuerHandler)))
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandler)))
	r.Method(http.MethodPost, "/bulk/redemption/", middleware.InstrumentHandler("BulkRedeemTokens", handlers.AppHandler(c.blindedTokenBulkRedeemHandler)))
	r.Method(http.MethodGet, "/{type}/redemption/", middleware.InstrumentHandler("CheckToken", handlers.AppHandler(c.blindedTokenRedemptionHandler)))
	return r
}
