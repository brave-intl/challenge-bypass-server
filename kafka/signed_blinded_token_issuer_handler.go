package kafka

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
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
SignedBlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.

	In cases where there are unrecoverable errors that prevent progress we will return nil.
	These permanent failure cases are different from cases where we encounter temporary
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

	log.Info().Msg("starting blinded token processor")

	defer func() {
		for i := 0; i < 20; i++ {
			log.Info().Msg("flush log")
		}
	}()

	log.Info().Msg("deserialize signing request")

	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		message := fmt.Sprintf(
			"request %s: failed avro deserialization",
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

	logger.Info().Msg("processing blinded token request for request_id")

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
		logger.Info().Msgf("processing request: %+v", request)
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
		logger.Info().Msgf("checking request cohort: %+v", request)
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

		logger.Info().Msgf("getting latest issuer: %+v with cohort: %+v", request.Issuer_type, request.Issuer_cohort)
		issuer, appErr := server.GetLatestIssuerKafka(context.Background(), request.Issuer_type, int16(request.Issuer_cohort))
		if appErr != nil {
			logger.Error().Err(appErr).Msg("error retrieving issuer")
			var processingError *utils.ProcessingError
			if errors.As(err, &processingError) {
				if processingError.Temporary {
					return err
				}
			}
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerInvalid,
				Associated_data:   request.Associated_data,
			})
			continue OUTER
		}

		logger.Info().Msgf("checking if issuer is version 3: %+v", issuer)
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

		logger.Info().Msgf("checking blinded tokens: %+v", request.Blinded_tokens)
		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			logger.Info().Msgf("blinded token: %+v", stringBlindedToken)
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
				break OUTER
			}
			blindedTokens = append(blindedTokens, &blindedToken)
		}

		logger.Info().Msgf("checking if issuer is time aware: %+v - %+v", issuer.Version, issuer.Buffer)
		// if the issuer is time aware, we need to approve tokens
		if issuer.Version == 3 && issuer.Buffer > 0 {
			// Calculate the number of tokens per signing key.
			// Given the mod check this should be a multiple of the total tokens in the request.
			var numT = len(request.Blinded_tokens) / (issuer.Buffer + issuer.Overlap)
			count := 0
			for i := 0; i < len(blindedTokens); i += numT {
				count++
				if count > len(issuer.Keys) {
					return fmt.Errorf("num keys %d: error invalid number of blindedTokens, not enough keys for signing request",
						len(issuer.Keys))
				}

				logger.Info().Msgf("version 3 issuer: %+v , numT: %+v", issuer, numT)
				var (
					blindedTokensSlice []*crypto.BlindedToken
					signingKey         *crypto.SigningKey
					validFrom          string
					validTo            string
				)

				signingKey = issuer.Keys[len(issuer.Keys)-count].SigningKey
				validFrom = issuer.Keys[len(issuer.Keys)-count].StartAt.Format(time.RFC3339)
				validTo = issuer.Keys[len(issuer.Keys)-count].EndAt.Format(time.RFC3339)

				pubKeyTxt, _ := signingKey.PublicKey().MarshalText()

				logger.Info().
					Str("len_keys", fmt.Sprintf("%d", len(issuer.Keys))).
					Str("count", fmt.Sprintf("%d", count)).
					Str("valid_from", validFrom).
					Str("valid_to", validTo).
					Str("signing_key", string(pubKeyTxt)).
					Msgf("signing with version 3 issuer key: %+v, numT: %+v", issuer.Keys[len(issuer.Keys)-count], numT)

				// Calculate the next step size to retrieve. Given previous checks end should never
				// be greater than the total number of tokens.
				end := i + numT
				if end > len(blindedTokens) {
					return fmt.Errorf("request %s: error invalid token step length",
						blindedTokenRequestSet.Request_id)
				}

				// Get the next group of tokens and approve
				blindedTokensSlice = blindedTokens[i:end]
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

				logger.Info().Msg("marshalling proof")

				marshaledDLEQProof, err := DLEQProof.MarshalText()
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

				var marshaledBlindedTokens []string
				for _, token := range blindedTokensSlice {
					marshaledToken, err := token.MarshalText()
					if err != nil {
						message := fmt.Sprintf("request %s: could not marshal blinded token slice to bytes: %s", blindedTokenRequestSet.Request_id, err)
						handlePermanentIssuanceError(
							message,
							marshaledBlindedTokens,
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
					marshaledBlindedTokens = append(marshaledBlindedTokens, string(marshaledToken))
				}

				var marshaledSignedTokens []string
				for _, token := range signedTokens {
					marshaledToken, err := token.MarshalText()
					if err != nil {
						message := fmt.Sprintf("request %s: could not marshal new tokens to bytes: %s", blindedTokenRequestSet.Request_id, err)
						handlePermanentIssuanceError(
							message,
							marshaledBlindedTokens,
							marshaledSignedTokens,
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
					marshaledSignedTokens = append(marshaledSignedTokens, string(marshaledToken))
				}

				logger.Info().Msg("getting public key")
				publicKey := signingKey.PublicKey()
				marshaledPublicKey, err := publicKey.MarshalText()
				if err != nil {
					message := fmt.Sprintf("request %s: could not marshal signing key: %s", blindedTokenRequestSet.Request_id, err)
					handlePermanentIssuanceError(
						message,
						marshaledBlindedTokens,
						marshaledSignedTokens,
						marshaledDLEQProof,
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
					Blinded_tokens:    marshaledBlindedTokens,
					Signed_tokens:     marshaledSignedTokens,
					Proof:             string(marshaledDLEQProof),
					Issuer_public_key: string(marshaledPublicKey),
					Valid_from:        &avroSchema.UnionNullString{String: validFrom, UnionType: avroSchema.UnionNullStringTypeEnumString},
					Valid_to:          &avroSchema.UnionNullString{String: validTo, UnionType: avroSchema.UnionNullStringTypeEnumString},
					Status:            issuerOk,
					Associated_data:   request.Associated_data,
				})
				logger.Info().
					Str("blinded_tokens", fmt.Sprintf("%+v", marshaledBlindedTokens)).
					Str("signed_tokens", fmt.Sprintf("%+v", marshaledSignedTokens)).
					Str("proof", string(marshaledDLEQProof)).
					Str("public_key", string(marshaledPublicKey)).
					Str("valid_from", string(validFrom)).
					Str("valid_to", string(validTo)).
					Msgf("signing with version 3 issuer key: %+v, numT: %+v", issuer.Keys[len(issuer.Keys)-count], numT)
			}
		} else {
			// otherwise, use the latest key for signing get the latest signing key from issuer
			var signingKey *crypto.SigningKey
			if len(issuer.Keys) > 0 {
				signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
			}

			logger.Info().Msgf("approving tokens: %+v", blindedTokens)
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

			marshaledDLEQProof, err := DLEQProof.MarshalText()
			if err != nil {
				message := fmt.Sprintf("request %s: could not marshal dleq proof: %s",
					blindedTokenRequestSet.Request_id, err)
				handlePermanentIssuanceError(
					message,
					nil,
					nil,
					marshaledDLEQProof,
					nil,
					issuerError,
					blindedTokenRequestSet.Request_id,
					msg,
					producer,
					&logger,
				)
				return nil
			}

			var marshaledBlindedTokens []string
			for _, token := range blindedTokens {
				marshaledToken, err := token.MarshalText()
				if err != nil {
					message := fmt.Sprintf("request %s: could not marshal blinded token slice to bytes: %s", blindedTokenRequestSet.Request_id, err)
					handlePermanentIssuanceError(
						message,
						marshaledBlindedTokens,
						nil,
						marshaledDLEQProof,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}
				marshaledBlindedTokens = append(marshaledBlindedTokens, string(marshaledToken))
			}

			var marshaledSignedTokens []string
			for _, token := range signedTokens {
				marshaledToken, err := token.MarshalText()
				if err != nil {
					message := fmt.Sprintf("error could not marshal new tokens to bytes: %s", err)
					handlePermanentIssuanceError(
						message,
						marshaledBlindedTokens,
						marshaledSignedTokens,
						marshaledDLEQProof,
						nil,
						issuerError,
						blindedTokenRequestSet.Request_id,
						msg,
						producer,
						&logger,
					)
					return nil
				}
				marshaledSignedTokens = append(marshaledSignedTokens, string(marshaledToken))
			}

			publicKey := signingKey.PublicKey()
			marshaledPublicKey, err := publicKey.MarshalText()
			if err != nil {
				message := fmt.Sprintf("error could not marshal signing key: %s", err)
				handlePermanentIssuanceError(
					message,
					marshaledBlindedTokens,
					marshaledSignedTokens,
					marshaledDLEQProof,
					marshaledPublicKey,
					issuerError,
					blindedTokenRequestSet.Request_id,
					msg,
					producer,
					&logger,
				)
				return nil
			}

			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Blinded_tokens:    marshaledBlindedTokens,
				Signed_tokens:     marshaledSignedTokens,
				Proof:             string(marshaledDLEQProof),
				Issuer_public_key: string(marshaledPublicKey),
				Status:            issuerOk,
				Associated_data:   request.Associated_data,
			})
		}
	}

	resultSet := avroSchema.SigningResultV2Set{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}
	logger.Info().Msgf("resultSet: %+v", resultSet)

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

	logger.Info().Msg("ending blinded token request processor loop")
	logger.Info().Msgf("about to emit: %+v", resultSet)
	err = Emit(producer, resultSetBuffer.Bytes(), log)
	if err != nil {
		message := fmt.Sprintf(
			"request %s: failed to emit to topic %s with result: %v",
			resultSet.Request_id,
			producer.Topic,
			resultSet,
		)
		log.Error().Err(err).Msgf(message)
		return err
	}
	logger.Info().Msgf("emitted: %+v", resultSet)

	return nil
}

// avroIssuerErrorResultFromError returns a ProcessingResult that is constructed from the
// provided values.
func avroIssuerErrorResultFromError(
	message string,
	marshaledBlindedTokens []string,
	marshaledSignedTokens []string,
	marshaledDLEQProof []byte,
	marshaledPublicKey []byte,
	issuerResultStatus int32,
	requestID string,
	msg kafka.Message,
	producer *kafka.Writer,
	logger *zerolog.Logger,
) *ProcessingResult {
	signingResult := avroSchema.SigningResultV2{
		Blinded_tokens:    marshaledBlindedTokens,
		Signed_tokens:     marshaledSignedTokens,
		Proof:             string(marshaledDLEQProof),
		Issuer_public_key: string(marshaledPublicKey),
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
	marshaledBlindedTokens []string,
	marshaledSignedTokens []string,
	marshaledDLEQProof []byte,
	marshaledPublicKey []byte,
	issuerResultStatus int32,
	requestID string,
	msg kafka.Message,
	producer *kafka.Writer,
	logger *zerolog.Logger,
) {
	processingResult := avroIssuerErrorResultFromError(
		message,
		marshaledBlindedTokens,
		marshaledSignedTokens,
		marshaledDLEQProof,
		marshaledPublicKey,
		issuerResultStatus,
		requestID,
		msg,
		producer,
		logger,
	)

	if err := Emit(producer, processingResult.Message, logger); err != nil {
		logger.Error().Err(err).Msg("failed to emit")
	}
}
