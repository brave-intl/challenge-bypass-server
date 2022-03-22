package kafka

import (
	"bytes"
	"fmt"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

/*
 BlindedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation
 tokens provided. If it encounters an error, it returns a utils.ProcessingError that indicates
 whether the error is temporary and the attmept should be retried, or if the error is
 permanent and the attempt should be abandoned.
*/
func SignedTokenRedeemHandler(
	msg kafka.Message,
	producer *kafka.Writer,
	tolerableEquivalence []cbpServer.Equivalence,
	server *cbpServer.Server,
	results chan *utils.ProcessingError,
	logger *zerolog.Logger,
) *utils.ProcessingError {
	data := msg.Value
	// Deserialize request into usable struct
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		message := fmt.Sprintf(
			"Request %s: Failed Avro deserialization",
			tokenRedeemRequestSet.Request_id,
		)
		return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
	}
	var redeemedTokenResults []avroSchema.RedeemResult
	// For the time being, we are only accepting one message at a time in this data set.
	// Therefore, we will error if more than a single message is present in the message.
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf("Request %s: Data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected.", tokenRedeemRequestSet.Request_id)
		return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		message := fmt.Sprintf(
			"Request %s: Failed to fetch all issuers",
			tokenRedeemRequestSet.Request_id,
		)
		return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
	}

	// Iterate over requests (only one at this point but the schema can support more
	// in the future if needed)
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			redemptionStatus       = avroSchema.RedeemResultStatusOk
			verifiedIssuer         = &cbpServer.Issuer{}
			verifiedCohort   int32 = 0
		)
		if request.Public_key == "" {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Missing public key",
				tokenRedeemRequestSet.Request_id,
			))
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
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Empty request",
				tokenRedeemRequestSet.Request_id,
			))
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
			message := fmt.Sprintf(
				"Request %s: Could not unmarshal text into preimage",
				tokenRedeemRequestSet.Request_id,
			)
			logger.Error().Err(err).Msg(message)
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   -1,
				Status:          avroSchema.RedeemResultStatusUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		}

		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf(
				"Request %s: Could not unmarshal text into verification signature",
				tokenRedeemRequestSet.Request_id,
			)
			logger.Error().Err(err).Msg(message)
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   -1,
				Status:          avroSchema.RedeemResultStatusUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		}

		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}
			// Only attempt token verification with the issuer that was provided.
			issuerPublicKey := issuer.SigningKey.PublicKey()
			marshaledPublicKey, err := issuerPublicKey.MarshalText()
			// Unmarshaling failure is a data issue and is probably permanent.
			if err != nil {
				message := fmt.Sprintf(
					"Request %s: Could not unmarshal issuer public key into text",
					tokenRedeemRequestSet.Request_id,
				)
				logger.Error().Err(err).Msg(message)
				redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
					Issuer_name:     "",
					Issuer_cohort:   -1,
					Status:          avroSchema.RedeemResultStatusUnverified,
					Associated_data: request.Associated_data,
				})
				continue
			}

			if string(marshaledPublicKey) == request.Public_key {
				if err := btd.VerifyTokenRedemption(
					&tokenPreimage,
					&verificationSignature,
					string(request.Binding),
					[]*crypto.SigningKey{issuer.SigningKey},
				); err != nil {
					redemptionStatus = avroSchema.RedeemResultStatusUnverified
				} else {
					redemptionStatus = avroSchema.RedeemResultStatusOk
					verifiedIssuer = &issuer
					verifiedCohort = int32(issuer.IssuerCohort)
					break
				}
			}
		}

		if !redemptionStatus == avroSchema.RedeemResultStatusOk {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Could not verify that the token redemption is valid",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			logger.Info().Msg(fmt.Sprintf(
				"Request %s: Validated",
				tokenRedeemRequestSet.Request_id,
			))
		}

		redemption, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, string(request.Binding), msg.Offset)
		if err != nil {
			message := fmt.Sprintf(
				"Request %s: Failed to check redemption equivalence",
				tokenRedeemRequestSet.Request_id,
			)
			return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
		}

		// If the discovered equivalence is not one of the tolerableEquivalence
		// options this redemption is considered a duplicate.
		if !containsEquivalnce(tolerableEquivalence, equivalence) {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Duplicate redemption: %e",
				tokenRedeemRequestSet.Request_id,
				err,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusDuplicate_redemption,
				Associated_data: request.Associated_data,
			})
			continue
		}

		if err := server.PersistRedemption(*redemption); err != nil {
			logger.Error().Err(err).Msg(fmt.Sprintf(
				"Request %s: Token redemption failed",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          avroSchema.RedeemResultStatusError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		logger.Info().Msg(fmt.Sprintf(
			"Request %s: Redeemed",
			tokenRedeemRequestSet.Request_id,
		))
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
		message := fmt.Sprintf(
			"Request %s: Failed to serialize ResultSet",
			tokenRedeemRequestSet.Request_id,
		)
		return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
	}

	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		message := fmt.Sprintf(
			"Request %s: Failed to emit results to topic %s",
			tokenRedeemRequestSet.Request_id,
			producer.Topic,
		)
		return utils.ProcessingErrorFromErrorWithMessage(err, message, msg, logger)
	}
	return nil
}

func containsEquivalnce(equivSlice []cbpServer.Equivalence, eqiv cbpServer.Equivalence) bool {
	for _, e := range equivSlice {
		if e == eqiv {
			return true
		}
	}

	return false
}
