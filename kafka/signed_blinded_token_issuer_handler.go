package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

/*
 SignedBlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
 In cases where there are unrecoverable errors that prevent progress we will return non-nil.
 These permanent failure cases are slightly different from cases where we encounter permanent
 errors inside the request data. For permanent failures inside the data processing loop we
 simply add the error to the results. However, temporary errors inside the loop should break
 the loop and return non-nil just like the errors outside the data processing loop. This is
 because future attempts to process permanent failure cases will not succeed.
 @TODO: It would be better for the Server implementation and the Kafka implementation of
 this behavior to share utility functions rather than passing an instance of the server
 as an argument here. That will require a bit of refactoring.
*/
func SignedBlindedTokenIssuerHandler(
	msg kafka.Message,
	producer *kafka.Writer,
	server *cbpServer.Server,
	log *zerolog.Logger,
) error {
	const (
		issuerOk      = 0
		issuerInvalid = 1
		issuerError   = 2
	)
	data := msg.Value
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		message := fmt.Sprintf(
			"request %s: failed Avro deserialization",
			blindedTokenRequestSet.Request_id,
		)
		handlePermanentIssuanceError(
			message,
			nil,
			nil,
			nil,
			nil,
			issuerError,
			blindedTokenRequestSet.Request_id,
			msg,
			producer,
			log,
		)
		return nil
	}

	logger := log.With().Str("request_id", blindedTokenRequestSet.Request_id).Logger()

	var blindedTokenResults []avroSchema.SigningResultV2
	if len(blindedTokenRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf(
			"request %s: data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected",
			blindedTokenRequestSet.Request_id,
		)
		handlePermanentIssuanceError(
			message,
			nil,
			nil,
			nil,
			nil,
			issuerError,
			blindedTokenRequestSet.Request_id,
			msg,
			producer,
			&logger,
		)
		return nil
	}

OUTER:
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_tokens == nil {
			logger.Error().Err(errors.New("blinded tokens is empty")).Msg("")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerError,
				Associated_data:   request.Associated_data,
			})
			continue OUTER
		}

		// check to see if issuer cohort will overflow
		if request.Issuer_cohort > math.MaxInt16 || request.Issuer_cohort < math.MinInt16 {
			logger.Error().Msg("invalid cohort")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerError,
				Associated_data:   request.Associated_data,
			})
			continue OUTER
		}

		issuer, err := server.GetLatestIssuerKafka(request.Issuer_type, int16(request.Issuer_cohort))
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving issuer")
			if err.Temporary {
				return err
			}
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerInvalid,
				Associated_data:   request.Associated_data,
			})
			continue OUTER
		}

		// if this is a time aware issuer, make sure the request contains the appropriate number of blinded tokens
		if issuer.Version == 3 && issuer.Buffer > 0 {
			if len(request.Blinded_tokens)%(issuer.Buffer+issuer.Overlap) != 0 {
				logger.Error().Err(errors.New("error request contains invalid number of blinded tokens")).Msg("")
				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
					Signed_tokens:     nil,
					Issuer_public_key: "",
					Status:            issuerError,
					Associated_data:   request.Associated_data,
				})
				continue OUTER
			}
		}

		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			blindedToken := crypto.BlindedToken{}
			err := blindedToken.UnmarshalText([]byte(stringBlindedToken))
			if err != nil {
				logger.Error().Err(fmt.Errorf("failed to unmarshal blinded tokens: %w", err)).
					Msg("signed blinded token issuer handler")
				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
					Signed_tokens:     nil,
					Issuer_public_key: "",
					Status:            issuerError,
					Associated_data:   request.Associated_data,
				})
				continue OUTER
			}
			blindedTokens = append(blindedTokens, &blindedToken)
		}

		// if the issuer is time aware, we need to approve tokens
		if issuer.Version == 3 && issuer.Buffer > 0 {
			// number of tokens per signing key
			var numT = len(request.Blinded_tokens) / (issuer.Buffer + issuer.Overlap)
			// sign tokens with all the keys in buffer+overlap
			for i := issuer.Buffer + issuer.Overlap; i > 0; i-- {
				var (
					blindedTokensSlice []*crypto.BlindedToken
					signingKey         *crypto.SigningKey
					validFrom          string
					validTo            string
				)

				signingKey = issuer.Keys[len(issuer.Keys)-i].SigningKey
				validFrom = issuer.Keys[len(issuer.Keys)-i].StartAt.Format(time.RFC3339)
				validTo = issuer.Keys[len(issuer.Keys)-i].EndAt.Format(time.RFC3339)

				blindedTokensSlice = blindedTokens[(i - numT):i]
				signedTokens, DLEQProof, err := btd.ApproveTokens(blindedTokensSlice, signingKey)
				if err != nil {
					// @TODO: If one token fails they will all fail. Assess this behavior
					logger.Error().Err(fmt.Errorf("error could not approve new tokens: %w", err)).
						Msg("signed blinded token issuer handler")
					blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
						Signed_tokens:     nil,
						Issuer_public_key: "",
						Status:            issuerError,
						Associated_data:   request.Associated_data,
					})
					break OUTER
				}

				marshalledDLEQProof, err := DLEQProof.MarshalText()
				if err != nil {
					message := fmt.Sprintf("request %s: could not marshal dleq proof: %s", blindedTokenRequestSet.Request_id, err)
					handlePermanentIssuanceError(
						message,
						nil,
						nil,
						nil,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}

				var marshalledBlindedTokens []string
				for _, token := range blindedTokensSlice {
					marshalledToken, err := token.MarshalText()
					if err != nil {
						message := fmt.Sprintf("request %s: could not marshal blinded token slice to bytes: %s", blindedTokenRequestSet.Request_id, err)
						handlePermanentIssuanceError(
							message,
							marshalledBlindedTokens,
							nil,
							nil,
							nil,
							issuerError,
							blindedTokenRequestSet.Request_id,
							msg,
							producer,
							&logger,
						)
						return nil
					}
					marshalledBlindedTokens = append(marshalledBlindedTokens, string(marshalledToken))
				}

				var marshalledSignedTokens []string
				for _, token := range signedTokens {
					marshalledToken, err := token.MarshalText()
					if err != nil {
						message := fmt.Sprintf("request %s: could not marshal new tokens to bytes: %s", blindedTokenRequestSet.Request_id, err)
						handlePermanentIssuanceError(
							message,
							marshalledBlindedTokens,
							marshalledSignedTokens,
							nil,
							nil,
							issuerError,
							blindedTokenRequestSet.Request_id,
							msg,
							producer,
							&logger,
						)
						return nil
					}
					marshalledSignedTokens = append(marshalledSignedTokens, string(marshalledToken))
				}

				publicKey := signingKey.PublicKey()
				marshalledPublicKey, err := publicKey.MarshalText()
				if err != nil {
					message := fmt.Sprintf("request %s: could not marshal signing key: %s", blindedTokenRequestSet.Request_id, err)
					handlePermanentIssuanceError(
						message,
						marshalledBlindedTokens,
						marshalledSignedTokens,
						marshalledDLEQProof,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}

				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
					Blinded_tokens:    marshalledBlindedTokens,
					Signed_tokens:     marshalledSignedTokens,
					Proof:             string(marshalledDLEQProof),
					Issuer_public_key: string(marshalledPublicKey),
					Valid_from:        &avroSchema.UnionNullString{String: validFrom, UnionType: avroSchema.UnionNullStringTypeEnumString},
					Valid_to:          &avroSchema.UnionNullString{String: validTo, UnionType: avroSchema.UnionNullStringTypeEnumString},
					Status:            issuerOk,
					Associated_data:   request.Associated_data,
				})
			}
		} else {
			// otherwise, use the latest key for signing get the latest signing key from issuer
			var signingKey *crypto.SigningKey
			if len(issuer.Keys) > 0 {
				signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
			}

			// @TODO: If one token fails they will all fail. Assess this behavior
			signedTokens, DLEQProof, err := btd.ApproveTokens(blindedTokens, signingKey)
			if err != nil {
				logger.Error().
					Err(fmt.Errorf("error could not approve new tokens: %w", err)).
					Msg("signed blinded token issuer handler")
				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
					Signed_tokens:     nil,
					Issuer_public_key: "",
					Status:            issuerError,
					Associated_data:   request.Associated_data,
				})
				continue OUTER
			}

			marshalledDLEQProof, err := DLEQProof.MarshalText()
			if err != nil {
				message := fmt.Sprintf("request %s: could not marshal dleq proof: %s",
					blindedTokenRequestSet.Request_id, err)
				handlePermanentIssuanceError(
					message,
					nil,
					nil,
					marshalledDLEQProof,
					nil,
					issuerError,
					blindedTokenRequestSet.Request_id,
					msg,
					producer,
					&logger,
				)
				return nil
			}

			var marshalledBlindedTokens []string
			for _, token := range blindedTokens {
				marshalledToken, err := token.MarshalText()
				if err != nil {
					message := fmt.Sprintf("request %s: could not marshal blinded token slice to bytes: %s", blindedTokenRequestSet.Request_id, err)
					handlePermanentIssuanceError(
						message,
						marshalledBlindedTokens,
						nil,
						marshalledDLEQProof,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}
				marshalledBlindedTokens = append(marshalledBlindedTokens, string(marshalledToken))
			}

			var marshalledSignedTokens []string
			for _, token := range signedTokens {
				marshalledToken, err := token.MarshalText()
				if err != nil {
					message := fmt.Sprintf("error could not marshal new tokens to bytes: %s", err)
					handlePermanentIssuanceError(
						message,
						marshalledBlindedTokens,
						marshalledSignedTokens,
						marshalledDLEQProof,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}
				marshalledSignedTokens = append(marshalledSignedTokens, string(marshalledToken))
			}

			publicKey := signingKey.PublicKey()
			marshalledPublicKey, err := publicKey.MarshalText()
			if err != nil {
				message := fmt.Sprintf("error could not marshal signing key: %s", err)
				handlePermanentIssuanceError(
					message,
					marshalledBlindedTokens,
					marshalledSignedTokens,
					marshalledDLEQProof,
					marshalledPublicKey,
					issuerError,
					blindedTokenRequestSet.Request_id,
					msg,
					producer,
					&logger,
				)
				return nil
			}

			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Blinded_tokens:    marshalledBlindedTokens,
				Signed_tokens:     marshalledSignedTokens,
				Proof:             string(marshalledDLEQProof),
				Issuer_public_key: string(marshalledPublicKey),
				Status:            issuerOk,
				Associated_data:   request.Associated_data,
			})
		}
	}

	resultSet := avroSchema.SigningResultV2Set{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}

	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		message := fmt.Sprintf(
			"request %s: failed to serialize ResultSet: %+v",
			blindedTokenRequestSet.Request_id,
			resultSet,
		)
		handlePermanentIssuanceError(
			message,
			nil,
			nil,
			nil,
			nil,
			issuerError,
			blindedTokenRequestSet.Request_id,
			msg,
			producer,
			&logger,
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

func avroIssuerErrorResultFromError(
	message string,
	marshalledBlindedTokens []string,
	marshalledSignedTokens []string,
	marshalledDLEQProof []byte,
	marshalledPublicKey []byte,
	issuerResultStatus int32,
	requestID string,
	msg kafka.Message,
	producer *kafka.Writer,
	logger *zerolog.Logger,
) *ProcessingResult {
	signingResult := avroSchema.SigningResultV2{
		Blinded_tokens:    marshalledBlindedTokens,
		Signed_tokens:     marshalledSignedTokens,
		Proof:             string(marshalledDLEQProof),
		Issuer_public_key: string(marshalledPublicKey),
		Status:            avroSchema.SigningResultV2Status(issuerResultStatus),
		Associated_data:   []byte(message),
	}
	resultSet := avroSchema.SigningResultV2Set{
		Request_id: "",
		Data:       []avroSchema.SigningResultV2{signingResult},
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

// handlePermanentIssuanceError is a convenience function to both generate a result from
// an errorand emit it.
func handlePermanentIssuanceError(
	message string,
	marshalledBlindedTokens []string,
	marshalledSignedTokens []string,
	marshalledDLEQProof []byte,
	marshalledPublicKey []byte,
	issuerResultStatus int32,
	requestID string,
	msg kafka.Message,
	producer *kafka.Writer,
	logger *zerolog.Logger,
) {

	processingResult := avroIssuerErrorResultFromError(
		message,
		marshalledBlindedTokens,
		marshalledSignedTokens,
		marshalledDLEQProof,
		marshalledPublicKey,
		issuerResultStatus,
		requestID,
		msg,
		producer,
		logger,
	)

	Emit(producer, processingResult.Message, logger)
	return
}
