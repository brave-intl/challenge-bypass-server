package kafka

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/model"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
)

/*
SignedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation

	tokens provided. If it encounters a permanent error, it emits a permanent result for that
	item. If the error is temporary, an error is returned to indicate that progress cannot be
	made.
*/

type SignedIssuerToken struct {
	issuer     model.Issuer
	signingKey *crypto.SigningKey
}

func SignedTokenRedeemHandler(
	ctx context.Context,
	msg kafka.Message,
	producer *kafka.Writer,
	server *cbpServer.Server,
	logger *slog.Logger,
) error {
	data := msg.Value
	// Deserialize request into usable struct
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		kafkaErrorTotal.Inc()
		return handlePermanentRedemptionError(
			ctx,
			fmt.Sprintf("failed avro deserialization"),
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			logger,
		)
	}

	reqLogger := logger.With(
		slog.String("request_id", tokenRedeemRequestSet.Request_id),
	)

	var redeemedTokenResults []avroSchema.RedeemResult
	// For the time being, we are only accepting one message at a time in this data set.
	// Therefore, we will error if more than a single message is present in the message.
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf("request %s: data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected", tokenRedeemRequestSet.Request_id)
		kafkaErrorTotal.Inc()
		return handlePermanentRedemptionError(
			ctx,
			message,
			errors.New("multiple messages"),
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			reqLogger,
		)
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		if processingError, ok := err.(*utils.ProcessingError); ok && processingError.Temporary {
			kafkaErrorTotal.Inc()
			return processingError
		}
		message := fmt.Sprintf("request %s: failed to fetch all issuers", tokenRedeemRequestSet.Request_id)
		kafkaErrorTotal.Inc()
		return handlePermanentRedemptionError(
			ctx,
			message,
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			reqLogger,
		)
	}

	// Create a lookup for issuers & signing keys based on public key.
	signedTokens := make(map[string]SignedIssuerToken)
	now := time.Now()

	for _, issuer := range issuers {
		if issuer.HasExpired(now) {
			continue
		}

		for _, issuerKey := range issuer.Keys {
			// Don't use keys outside their start/end dates
			if issuerTimeIsNotValid(issuerKey.StartAt, issuerKey.EndAt) {
				continue
			}

			signingKey := issuerKey.CryptoSigningKey()
			issuerPublicKey := signingKey.PublicKey()
			marshaledPublicKey, mErr := issuerPublicKey.MarshalText()
			// Unmarshalling failure is a data issue and is probably permanent.
			if mErr != nil {
				message := fmt.Sprintf("request %s: could not unmarshal issuer public key into text", tokenRedeemRequestSet.Request_id)
				kafkaErrorTotal.Inc()
				return handlePermanentRedemptionError(
					ctx,
					message,
					err,
					msg,
					producer,
					tokenRedeemRequestSet.Request_id,
					int32(avroSchema.RedeemResultStatusError),
					reqLogger,
				)
			}

			signedTokens[string(marshaledPublicKey)] = SignedIssuerToken{
				issuer:     issuer,
				signingKey: signingKey,
			}
		}
	}

	// Iterate over requests (only one at this point but the schema can support more
	// in the future if needed)
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			verified       = false
			verifiedIssuer = &model.Issuer{}
			verifiedCohort int32
		)
		if request.Public_key == "" {
			reqLogger.Error("missing public key", slog.Any("error", err))
			kafkaErrorTotal.Inc()
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		// preimage, signature, and binding are all required to proceed
		if request.Token_preimage == "" || request.Signature == "" || request.Binding == "" {
			reqLogger.Error("empty request", slog.Any("error", err))
			kafkaErrorTotal.Inc()
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		tokenPreimage := crypto.TokenPreimage{}
		err = tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf("request %s: could not unmarshal text into preimage", tokenRedeemRequestSet.Request_id)
			kafkaErrorTotal.Inc()
			return handlePermanentRedemptionError(
				ctx,
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				reqLogger,
			)
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf("request %s: could not unmarshal text into verification signature", tokenRedeemRequestSet.Request_id)
			kafkaErrorTotal.Inc()
			return handlePermanentRedemptionError(
				ctx,
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				reqLogger,
			)
		}

		if signedToken, ok := signedTokens[request.Public_key]; ok {
			reqLogger.Debug(
				"attempting token redemption verification",
				"publicKey", request.Public_key,
			)

			issuer := signedToken.issuer
			if err := btd.VerifyTokenRedemption(
				&tokenPreimage,
				&verificationSignature,
				request.Binding,
				[]*crypto.SigningKey{signedToken.signingKey},
			); err == nil {
				verified = true
				verifiedIssuer = &issuer
				verifiedCohort = int32(issuer.IssuerCohort)
			}
		}

		if !verified {
			reqLogger.Error("could not verify that the token redemption is valid")
			kafkaErrorTotal.Inc()
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			reqLogger.Info("token validated")
		}
		redemption, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, request.Binding, msg.Offset)
		if err != nil {
			var processingError *utils.ProcessingError
			if errors.As(err, &processingError) {
				if processingError.Temporary {
					return err
				}
			}
			message := fmt.Sprintf("request %s: failed to check redemption equivalence", tokenRedeemRequestSet.Request_id)
			kafkaErrorTotal.Inc()
			return handlePermanentRedemptionError(
				ctx,
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				reqLogger,
			)
		}

		// Continue if there is a duplicate
		switch equivalence {
		case cbpServer.IDEquivalence:
			duplicateRedemptionTotal.Inc()
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     verifiedIssuer.IssuerType,
				Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
				Status:          avroSchema.RedeemResultStatusDuplicate_redemption,
				Associated_data: request.Associated_data,
			})
			continue
		case cbpServer.BindingEquivalence:
			idempotentRedemptionTotal.Inc()
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     verifiedIssuer.IssuerType,
				Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
				Status:          avroSchema.RedeemResultStatusIdempotent_redemption,
				Associated_data: request.Associated_data,
			})
			continue
		}

		// If no equivalent record was found in the database, persist.
		if err := server.PersistRedemption(*redemption); err != nil {
			reqLogger.Error("token redemption failed", slog.Any("error", err))
			kafkaErrorTotal.Inc()
			// In the unlikely event that there is a race condition that results
			// in a duplicate error upon save that was not detected previously
			// we will check equivalence upon receipt of a duplicate error.
			if strings.Contains(err.Error(), "Duplicate") {
				_, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, request.Binding, msg.Offset)
				if err != nil {
					message := fmt.Sprintf("request %s: failed to check redemption equivalence", tokenRedeemRequestSet.Request_id)
					var processingError *utils.ProcessingError
					if errors.As(err, &processingError) {
						if processingError.Temporary {
							return err
						}
					}
					return handlePermanentRedemptionError(
						ctx,
						message,
						err,
						msg,
						producer,
						tokenRedeemRequestSet.Request_id,
						int32(avroSchema.RedeemResultStatusError),
						reqLogger,
					)
				}
				reqLogger.Error("duplicate redemption", slog.Any("error", err))
				// Continue if there is a duplicate
				switch equivalence {
				case cbpServer.IDEquivalence:
					redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
						Issuer_name:     verifiedIssuer.IssuerType,
						Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
						Status:          avroSchema.RedeemResultStatusDuplicate_redemption,
						Associated_data: request.Associated_data,
					})
					continue
				case cbpServer.BindingEquivalence:
					redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
						Issuer_name:     verifiedIssuer.IssuerType,
						Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
						Status:          avroSchema.RedeemResultStatusIdempotent_redemption,
						Associated_data: request.Associated_data,
					})
					continue
				}
			}
			reqLogger.Error("could not mark token redemption")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     verifiedIssuer.IssuerType,
				Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
				Status:          avroSchema.RedeemResultStatusError,
				Associated_data: request.Associated_data,
			})
			continue
		}
		reqLogger.Debug("redeemed")
		issuerName := verifiedIssuer.IssuerType
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_name:     issuerName,
			Issuer_cohort:   verifiedCohort,
			Status:          avroSchema.RedeemResultStatusOk,
			Associated_data: request.Associated_data,
		})
	}
	resultSet := avroSchema.RedeemResultSet{
		Request_id: tokenRedeemRequestSet.Request_id,
		Data:       redeemedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		message := fmt.Sprintf("request %s: failed to serialize result set", tokenRedeemRequestSet.Request_id)
		kafkaErrorTotal.Inc()
		return handlePermanentRedemptionError(
			ctx,
			message,
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			reqLogger,
		)
	}

	err = Emit(ctx, producer, resultSetBuffer.Bytes(), reqLogger)
	if err != nil {
		reqLogger.Error("failed to emit results to topic",
			"topic", producer.Topic,
			slog.Any("error", err),
		)
		kafkaErrorTotal.Inc()
		return err
	}

	return nil
}

func issuerTimeIsNotValid(start *time.Time, end *time.Time) bool {
	if start != nil && end != nil {
		now := time.Now()

		startIsNotZeroAndAfterNow := !start.IsZero() && start.After(now)
		endIsNotZeroAndBeforeNow := !end.IsZero() && end.Before(now)

		return startIsNotZeroAndAfterNow || endIsNotZeroAndBeforeNow
	}

	// Both times being nil is valid
	bothTimesAreNil := start == nil && end == nil
	return !bothTimesAreNil
}

// avroRedeemErrorResultFromError returns a message to emit that is constructed
// from the provided values.
func avroRedeemErrorResultFromError(
	message string,
	msg kafka.Message,
	requestID string,
	redeemResultStatus int32,
) []byte {
	redeemResult := avroSchema.RedeemResult{
		Issuer_name:     "",
		Issuer_cohort:   0,
		Status:          avroSchema.RedeemResultStatus(redeemResultStatus),
		Associated_data: []byte(message),
	}
	resultSet := avroSchema.RedeemResultSet{
		Request_id: "",
		Data:       []avroSchema.RedeemResult{redeemResult},
	}
	var resultSetBuffer bytes.Buffer
	err := resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		message := fmt.Sprintf("request %s: failed to serialize result set", requestID)
		kafkaErrorTotal.Inc()
		return []byte(message)
	}
	return resultSetBuffer.Bytes()
}

// handleRedemptionError is a convenience function that executes a call pattern shared
// when handling all errors in the redeem flow
func handlePermanentRedemptionError(
	ctx context.Context,
	message string,
	cause error,
	msg kafka.Message,
	producer *kafka.Writer,
	requestID string,
	redeemResultStatus int32,
	logger *slog.Logger,
) error {
	logger.Error("encountered permanent redemption failure", slog.Any("error", message))
	kafkaErrorTotal.Inc()
	toEmit := avroRedeemErrorResultFromError(
		message,
		msg,
		requestID,
		int32(avroSchema.RedeemResultStatusError),
	)
	if err := Emit(ctx, producer, toEmit, logger); err != nil {
		kafkaErrorTotal.Inc()
		logger.Error("failed to emit", slog.Any("error", err))
	}
	// TODO: consider returning err here as failing to emit error should not
	// commit messages the same way as failing to emit a success does not
	// commit.
	return nil
}
