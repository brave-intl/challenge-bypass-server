package kafka

import (
	"bytes"
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
 tokens provided. If it encounters an error, it returns a ProcessingError that indicates
 whether the error is temporary and the attmept should be retried, or if the error is
 permanent and the attempt should be abandoned.
*/
func SignedTokenRedeemHandler(
	msg kafka.Message,
	producer *kafka.Writer,
	server *cbpServer.Server,
	log *zerolog.Logger,
) (*ProcessingResult, *utils.ProcessingError) {
	const (
		redeemOk                     = 0
		redeemDuplicateRedemptionID  = 1
		redeemUnverified             = 2
		redeemError                  = 3
		redeemDuplicateRedemptionAll = 4
	)
	data := msg.Value
	// Deserialize request into usable struct
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		message := fmt.Sprintf("request %s: failed avro deserialization", tokenRedeemRequestSet.Request_id)
		return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
	}

	logger := log.With().Str("request_id", tokenRedeemRequestSet.Request_id).Logger()

	var redeemedTokenResults []avroSchema.RedeemResult
	// For the time being, we are only accepting one message at a time in this data set.
	// Therefore, we will error if more than a single message is present in the message.
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf("request %s: data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected", tokenRedeemRequestSet.Request_id)
		return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		message := fmt.Sprintf("request %s: failed to fetch all issuers", tokenRedeemRequestSet.Request_id)
		return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
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
				Status:          redeemError,
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
				Status:          redeemError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		tokenPreimage := crypto.TokenPreimage{}
		err = tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf("request %s: could not unmarshal text into preimage", tokenRedeemRequestSet.Request_id)
			return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		// Unmarshaling failure is a data issue and is probably permanent.
		if err != nil {
			message := fmt.Sprintf("request %s: could not unmarshal text into verification signature", tokenRedeemRequestSet.Request_id)
			return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
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
				return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
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
				Status:          redeemUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			logger.Info().Msg(fmt.Sprintf("request %s: validated", tokenRedeemRequestSet.Request_id))
		}
		redemption, equivalence, err := server.CheckRedeemedTokenEquivalence(verifiedIssuer, &tokenPreimage, string(request.Binding), msg.Offset)
		if err != nil {
			message := fmt.Sprintf("request %s: failed to check redemption equivalence", tokenRedeemRequestSet.Request_id)
			return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
		}

		// Continue if there is a duplicate
		switch equivalence {
		case cbpServer.IDEquivalence:
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemDuplicateRedemptionID,
				Associated_data: request.Associated_data,
			})
			continue
		case cbpServer.IDAndAllValueEquivalence:
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemDuplicateRedemptionAll,
				Associated_data: request.Associated_data,
			})
			continue
		}

		if err := server.PersistRedemption(*redemption); err != nil {
			logger.Error().Err(err).Msgf("request %s: token redemption failed: %e", tokenRedeemRequestSet.Request_id, err)
			if strings.Contains(err.Error(), "Duplicate") {
				logger.Error().Err(fmt.Errorf("request %s: duplicate redemption: %w",
					tokenRedeemRequestSet.Request_id, err)).
					Msg("signed token redeem handler")
				redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
					Issuer_name:     "",
					Issuer_cohort:   0,
					Status:          redeemDuplicateRedemptionID,
					Associated_data: request.Associated_data,
				})
			}
			logger.Error().Err(fmt.Errorf("request %s: could not mark token redemption",
				tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemError,
				Associated_data: request.Associated_data,
			})
			continue
		}
		logger.Trace().Msgf("request %s: redeemed", tokenRedeemRequestSet.Request_id)
		issuerName := verifiedIssuer.IssuerType
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_name:     issuerName,
			Issuer_cohort:   verifiedCohort,
			Status:          redeemOk,
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
		return ResultAndErrorFromError(err, msg, message, producer, tokenRedeemRequestSet.Request_id, log)
	}

	return &ProcessingResult{
		Message:        resultSetBuffer.Bytes(),
		ResultProducer: producer,
		RequestID:      tokenRedeemRequestSet.Request_id,
	}, nil
}

func containsEquivalnce(equivSlice []cbpServer.Equivalence, eqiv cbpServer.Equivalence) bool {
	for _, e := range equivSlice {
		if e == eqiv {
			return true
		}
	}

	return false
}
