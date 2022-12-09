package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

/*
SignedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation
 tokens provided. If it encounters a permanent error, it emits a permanent result for that
 item. If the error is temporary, an error is returned to indicate that progress cannot be
 made.
*/
func SignedTokenRedeemHandler(
	msg kafka.Message,
	producer *kafka.Writer,
	server *cbpServer.Server,
	log *zerolog.Logger,
) error {
	data := msg.Value
	// Deserialize request into usable struct
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		message := fmt.Sprintf("request %s: failed avro deserialization", tokenRedeemRequestSet.Request_id)
		handlePermanentRedemptionError(
			message,
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			log,
		)
		return nil
	}

	logger := log.With().Str("request_id", tokenRedeemRequestSet.Request_id).Logger()

	var redeemedTokenResults []avroSchema.RedeemResult
	// For the time being, we are only accepting one message at a time in this data set.
	// Therefore, we will error if more than a single message is present in the message.
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf("request %s: data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected", tokenRedeemRequestSet.Request_id)
		handlePermanentRedemptionError(
			message,
			errors.New("multiple messages"),
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			log,
		)
		return nil
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		if processingError, ok := err.(*utils.ProcessingError); ok && processingError.Temporary {
			return processingError
		}
		message := fmt.Sprintf("request %s: failed to fetch all issuers", tokenRedeemRequestSet.Request_id)
		handlePermanentRedemptionError(
			message,
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			log,
		)
		return nil
	}

	// Iterate over requests (only one at this point but the schema can support more
	// in the future if needed)
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			verified       = false
			verifiedIssuer = &cbpServer.Issuer{}
			verifiedCohort int32
		)
		if request.Public_key == "" {
			logger.Error().
				Err(fmt.Errorf("request %s: missing public key", tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
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
			logger.Error().
				Err(fmt.Errorf("request %s: empty request", tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
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
			handlePermanentRedemptionError(
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				log,
			)
			return nil
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf("request %s: could not unmarshal text into verification signature", tokenRedeemRequestSet.Request_id)
			handlePermanentRedemptionError(
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				log,
			)
			return nil
		}
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}

			// get latest signing key from issuer
			var signingKey *crypto.SigningKey
			if issuer.Version < 3 {
				// non-time aware verification use latest issuer key
				if len(issuer.Keys) > 0 {
					signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
				}
			} else if issuer.Version == 3 {
				// iterate through keys until we find the one that is valid now
				for _, k := range issuer.Keys {
					if k.StartAt.Before(time.Now()) && k.EndAt.After(time.Now()) {
						signingKey = k.SigningKey
						break
					}
				}
			}
			// Only attempt token verification with the issuer that was provided.
			issuerPublicKey := signingKey.PublicKey()
			marshaledPublicKey, err := issuerPublicKey.MarshalText()
			// Unmarshaling failure is a data issue and is probably permanent.
			if err != nil {
				message := fmt.Sprintf("request %s: could not unmarshal issuer public key into text", tokenRedeemRequestSet.Request_id)
				handlePermanentRedemptionError(
					message,
					err,
					msg,
					producer,
					tokenRedeemRequestSet.Request_id,
					int32(avroSchema.RedeemResultStatusError),
					log,
				)
				return nil
			}

			logger.Trace().
				Msgf("request %s: issuer: %s, request: %s", tokenRedeemRequestSet.Request_id,
					string(marshaledPublicKey), request.Public_key)

			if string(marshaledPublicKey) == request.Public_key {
				if err := btd.VerifyTokenRedemption(
					&tokenPreimage,
					&verificationSignature,
					request.Binding,
					[]*crypto.SigningKey{signingKey},
				); err != nil {
					verified = false
				} else {
					verified = true
					verifiedIssuer = &issuer
					verifiedCohort = int32(issuer.IssuerCohort)
					break
				}
			}
		}

		if !verified {
			logger.Error().
				Err(fmt.Errorf("request %s: could not verify that the token redemption is valid",
					tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			logger.Info().Msg(fmt.Sprintf("request %s: validated", tokenRedeemRequestSet.Request_id))
		}
		redemption, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, string(request.Binding), msg.Offset)
		if err != nil {
			var processingError *utils.ProcessingError
			if errors.As(err, &processingError) {
				if processingError.Temporary {
					return err
				}
			}
			message := fmt.Sprintf("request %s: failed to check redemption equivalence", tokenRedeemRequestSet.Request_id)
			handlePermanentRedemptionError(
				message,
				err,
				msg,
				producer,
				tokenRedeemRequestSet.Request_id,
				int32(avroSchema.RedeemResultStatusError),
				log,
			)
			return nil
		}

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

		// If no equivalent record was found in the database, persist.
		if err := server.PersistRedemption(*redemption); err != nil {
			logger.Error().Err(err).Msgf("request %s: token redemption failed: %e", tokenRedeemRequestSet.Request_id, err)
			// In the unlikely event that there is a race condition that results
			// in a duplicate error upon save that was not detected previously
			// we will check equivalence upon receipt of a duplicate error.
			if strings.Contains(err.Error(), "Duplicate") {
				_, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, string(request.Binding), msg.Offset)
				if err != nil {
					message := fmt.Sprintf("request %s: failed to check redemption equivalence", tokenRedeemRequestSet.Request_id)
					var processingError *utils.ProcessingError
					if errors.As(err, &processingError) {
						if processingError.Temporary {
							return err
						}
					}
					handlePermanentRedemptionError(
						message,
						err,
						msg,
						producer,
						tokenRedeemRequestSet.Request_id,
						int32(avroSchema.RedeemResultStatusError),
						log,
					)
					return nil
				}
				logger.Error().Err(fmt.Errorf("request %s: duplicate redemption: %w",
					tokenRedeemRequestSet.Request_id, err)).
					Msg("signed token redeem handler")
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
			logger.Error().Err(fmt.Errorf("request %s: could not mark token redemption",
				tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     verifiedIssuer.IssuerType,
				Issuer_cohort:   int32(verifiedIssuer.IssuerCohort),
				Status:          avroSchema.RedeemResultStatusError,
				Associated_data: request.Associated_data,
			})
			continue
		}
		logger.Trace().Msgf("request %s: redeemed", tokenRedeemRequestSet.Request_id)
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
		handlePermanentRedemptionError(
			message,
			err,
			msg,
			producer,
			tokenRedeemRequestSet.Request_id,
			int32(avroSchema.RedeemResultStatusError),
			log,
		)
		return nil
	}

	err = Emit(producer, resultSetBuffer.Bytes(), log)
	if err != nil {
		message := fmt.Sprintf(
			"request %s: failed to emit results to topic %s",
			resultSet.Request_id,
			producer.Topic,
		)
		log.Error().Err(err).Msgf(message)
		return err
	}

	return nil
}

// avroRedeemErrorResultFromError returns a ProcessingResult that is constructed from the
// provided values.
func avroRedeemErrorResultFromError(
	message string,
	msg kafka.Message,
	producer *kafka.Writer,
	requestID string,
	redeemResultStatus int32,
	logger *zerolog.Logger,
) *ProcessingResult {
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
		return &ProcessingResult{
			Message:        []byte(message),
			ResultProducer: producer,
			RequestID:      requestID,
		}
	}
	return &ProcessingResult{
		Message:        []byte(message),
		ResultProducer: producer,
		RequestID:      requestID,
	}
}

// handleRedemptionError is a convenience function that executes a call pattern shared
// when handling all errors in the redeem flow
func handlePermanentRedemptionError(
	message string,
	cause error,
	msg kafka.Message,
	producer *kafka.Writer,
	requestID string,
	redeemResultStatus int32,
	logger *zerolog.Logger,
) {
	logger.Error().Err(cause).Msgf("encountered permanent redemption failure: %v", message)
	processingResult := avroRedeemErrorResultFromError(
		message,
		msg,
		producer,
		requestID,
		int32(avroSchema.RedeemResultStatusError),
		logger,
	)
	if err := Emit(producer, processingResult.Message, logger); err != nil {
		logger.Error().Err(err).Msg("failed to emit")
	}
}
