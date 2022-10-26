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

// SignedBlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
// @TODO: It would be better for the Server implementation and the Kafka implementation of
// this behavior to share utility functions rather than passing an instance of the server
// as an argument here. That will require a bit of refactoring.
func SignedBlindedTokenIssuerHandler(data []byte, producer *kafka.Writer, server *cbpServer.Server, log *zerolog.Logger) error {
	const (
		issuerOk      = 0
		issuerInvalid = 1
		issuerError   = 2
	)

	log.Debug().Msg("starting blinded token processor")

	log.Info().Msg("deserialize signing request")

	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request %s: failed avro deserialization: %w", blindedTokenRequestSet.Request_id, err)
	}

	logger := log.With().Str("request_id", blindedTokenRequestSet.Request_id).Logger()

	logger.Debug().Msg("processing blinded token request for request_id")

	var blindedTokenResults []avroSchema.SigningResultV2
	if len(blindedTokenRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return fmt.Errorf(`request %s: data array unexpectedly contained more than a single message. this array is 
						intended to make future extension easier, but no more than a single value is currently expected`,
			blindedTokenRequestSet.Request_id)
	}

OUTER:
	for _, request := range blindedTokenRequestSet.Data {
		logger.Debug().Msgf("processing request: %+v", request)
		if request.Blinded_tokens == nil {
			logger.Error().Err(errors.New("blinded tokens is empty")).Msg("")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerError,
				Associated_data:   request.Associated_data,
			})
			break OUTER
		}

		// check to see if issuer cohort will overflow
		logger.Debug().Msgf("checking request cohort: %+v", request)
		if request.Issuer_cohort > math.MaxInt16 || request.Issuer_cohort < math.MinInt16 {
			logger.Error().Msg("invalid cohort")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerError,
				Associated_data:   request.Associated_data,
			})
			break OUTER
		}

		logger.Debug().Msgf("getting latest issuer: %+v - %+v", request.Issuer_type, request.Issuer_cohort)
		issuer, appErr := server.GetLatestIssuer(request.Issuer_type, int16(request.Issuer_cohort))
		if appErr != nil {
			logger.Error().Err(appErr).Msg("error retrieving issuer")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerInvalid,
				Associated_data:   request.Associated_data,
			})
			break OUTER
		}

		logger.Debug().Msgf("checking if issuer is version 3: %+v", issuer)
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
				break OUTER
			}
		}

		logger.Debug().Msgf("checking blinded tokens: %+v", request.Blinded_tokens)
		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			logger.Debug().Msgf("blinded token: %+v", stringBlindedToken)
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

		logger.Debug().Msgf("checking if issuer is time aware: %+v - %+v", issuer.Version, issuer.Buffer)
		// if the issuer is time aware, we need to approve tokens
		if issuer.Version == 3 && issuer.Buffer > 0 {
			// Calculate the number of tokens per signing key.
			// Given the mod check this should be a multiple of the total tokens in the request.
			var numT = len(request.Blinded_tokens) / (issuer.Buffer + issuer.Overlap)
			count := 0
			for i := 0; i < len(blindedTokens); i += numT {
				count++

				logger.Debug().Msgf("version 3 issuer: %+v , numT: %+v", issuer, numT)
				var (
					blindedTokensSlice []*crypto.BlindedToken
					signingKey         *crypto.SigningKey
					validFrom          string
					validTo            string
				)

				signingKey = issuer.Keys[len(issuer.Keys)-count].SigningKey
				validFrom = issuer.Keys[len(issuer.Keys)-count].StartAt.Format(time.RFC3339)
				validTo = issuer.Keys[len(issuer.Keys)-count].EndAt.Format(time.RFC3339)

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

				logger.Debug().Msg("marshalling proof")

				marshaledDLEQProof, err := DLEQProof.MarshalText()
				if err != nil {
					return fmt.Errorf("request %s: could not marshal dleq proof: %w", blindedTokenRequestSet.Request_id, err)
				}

				var marshalledBlindedTokens []string
				for _, token := range blindedTokensSlice {
					marshaledToken, err := token.MarshalText()
					if err != nil {
						return fmt.Errorf("request %s: could not marshal blinded token slice to bytes: %w",
							blindedTokenRequestSet.Request_id, err)
					}
					marshalledBlindedTokens = append(marshalledBlindedTokens, string(marshaledToken[:]))
				}

				var marshaledSignedTokens []string
				for _, token := range signedTokens {
					marshaledToken, err := token.MarshalText()
					if err != nil {
						return fmt.Errorf("request %s: could not marshal new tokens to bytes: %w",
							blindedTokenRequestSet.Request_id, err)
					}
					marshaledSignedTokens = append(marshaledSignedTokens, string(marshaledToken[:]))
				}

				logger.Debug().Msg("getting public key")
				publicKey := signingKey.PublicKey()
				marshaledPublicKey, err := publicKey.MarshalText()
				if err != nil {
					return fmt.Errorf("request %s: could not marshal signing key: %w",
						blindedTokenRequestSet.Request_id, err)
				}

				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
					Blinded_tokens:    marshalledBlindedTokens,
					Signed_tokens:     marshaledSignedTokens,
					Proof:             string(marshaledDLEQProof),
					Issuer_public_key: string(marshaledPublicKey),
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

			logger.Debug().Msgf("approving tokens: %+v", blindedTokens)
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
				break OUTER
			}

			marshaledDLEQProof, err := DLEQProof.MarshalText()
			if err != nil {
				return fmt.Errorf("request %s: could not marshal dleq proof: %w",
					blindedTokenRequestSet.Request_id, err)
			}

			var marshalledBlindedTokens []string
			for _, token := range blindedTokens {
				marshaledToken, err := token.MarshalText()
				if err != nil {
					return fmt.Errorf("request %s: could not marshal blinded token slice to bytes: %w",
						blindedTokenRequestSet.Request_id, err)
				}
				marshalledBlindedTokens = append(marshalledBlindedTokens, string(marshaledToken[:]))
			}

			var marshaledSignedTokens []string
			for _, token := range signedTokens {
				marshaledToken, err := token.MarshalText()
				if err != nil {
					return fmt.Errorf("error could not marshal new tokens to bytes: %w", err)
				}
				marshaledSignedTokens = append(marshaledSignedTokens, string(marshaledToken[:]))
			}

			publicKey := signingKey.PublicKey()
			marshaledPublicKey, err := publicKey.MarshalText()
			if err != nil {
				return fmt.Errorf("error could not marshal signing key: %w", err)
			}

			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResultV2{
				Blinded_tokens:    marshalledBlindedTokens,
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
	logger.Debug().Msgf("resultSet: %+v", resultSet)

	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		return fmt.Errorf("request %s: failed to serialize result set: %s: %w",
			blindedTokenRequestSet.Request_id, resultSetBuffer.String(), err)
	}

	logger.Debug().Msg("ending blinded token request processor loop")
	logger.Debug().Msgf("about to emit: %+v", resultSet)
	err = Emit(producer, resultSetBuffer.Bytes(), log)
	if err != nil {
		logger.Error().Msgf("failed to emit: %+v", resultSet)
		return fmt.Errorf("request %s: failed to emit results to topic %s: %w",
			blindedTokenRequestSet.Request_id, producer.Topic, err)
	}
	logger.Debug().Msgf("emitted: %+v", resultSet)

	return nil
}
