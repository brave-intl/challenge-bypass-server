package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	batgo_handlers "github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

/*
 BlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
 @TODO: It would be better for the Server implementation and the Kafka implementation of
 this behavior to share utility functions rather than passing an instance of the server
 as an argument here. That will require a bit of refactoring.
*/
func SignedBlindedTokenIssuerHandler(
	data []byte,
	producer *kafka.Writer,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) []*batgo_handlers.AppError {
	var errorSet []*batgo_handlers.AppError
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		errorSet = append(errorSet, batgo_handlers.WrapError(
			err,
			fmt.Sprintf(
				"Request %s: Failed Avro deserialization",
				blindedTokenRequestSet.Request_id,
			),
			PERMANENT,
		))
		return errorSet
	}
	if len(blindedTokenRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		message := fmt.Sprintf("Request %s: Data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected.", blindedTokenRequestSet.Request_id)
		errorSet = append(errorSet, batgo_handlers.WrapError(
			errors.New(message),
			message,
			PERMANENT,
		))
		return errorSet
	}
	var wg sync.WaitGroup
	blindedTokenResultsChannel := make(chan avroSchema.SigningResult)
	errorChannel := make(chan *batgo_handlers.AppError)

	for _, request := range blindedTokenRequestSet.Data {
		wg.Add(1)
		go handleBlindedTokenRequest(
			wg,
			request,
			blindedTokenRequestSet.Request_id,
			blindedTokenResultsChannel,
			errorChannel,
			server,
			logger,
		)(wg)
	}
	wg.Wait()

	var blindedTokenResults []avroSchema.SigningResult
	for blindedTokenResult := range blindedTokenResultsChannel {
		blindedTokenResults = append(blindedTokenResults, blindedTokenResult)
	}
	for errorChannelResult := range errorChannel {
		errorSet = append(errorSet, errorChannelResult)
	}

	resultSet := avroSchema.SigningResultSet{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		errorSet = append(errorSet, batgo_handlers.WrapError(
			err,
			fmt.Sprintf(
				"Request %s: Failed to serialize ResultSet: %s",
				blindedTokenRequestSet.Request_id,
				resultSet,
			),
			PERMANENT,
		))
		return errorSet
	}
	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		errorSet = append(errorSet, batgo_handlers.WrapError(
			err,
			fmt.Sprintf(
				"Request %s: Failed to emit results to topic %s",
				blindedTokenRequestSet.Request_id,
				producer.Topic,
			),
			TEMPORARY,
		))
		return errorSet
	}
	return errorSet
}

func handleBlindedTokenRequest(
	wg sync.WaitGroup,
	request avroSchema.SigningRequest,
	requestId string,
	blindedTokenResults chan avroSchema.SigningResult,
	errorChannel chan *batgo_handlers.AppError,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) {
	defer wg.Done()
	const (
		OK             = 0
		INVALID_ISSUER = 1
		ERROR          = 2
	)
	if request.Blinded_tokens == nil {
		message := fmt.Sprintf("Request %s: Empty request", requestId)
		errorChannel <- batgo_handlers.WrapError(
			errors.New(message),
			message,
			PERMANENT,
		)
	}

	if request.Issuer_cohort != 0 && request.Issuer_cohort != 1 {
		message := fmt.Sprintf(
			"Request %s: Provided cohort is not supported: %d",
			requestId,
			request.Issuer_cohort,
		)
		errorChannel <- batgo_handlers.WrapError(
			errors.New(message),
			message,
			PERMANENT,
		)
	}

	issuer, appErr := server.GetLatestIssuer(request.Issuer_type, int(request.Issuer_cohort))
	if appErr != nil {
		blindedTokenResults <- avroSchema.SigningResult{
			Signed_tokens:     nil,
			Issuer_public_key: "",
			Status:            INVALID_ISSUER,
			Associated_data:   request.Associated_data,
		}
	}

	var blindedTokens []*crypto.BlindedToken
	// Iterate over the provided tokens and create data structure from them,
	// grouping into a slice for approval
	for _, stringBlindedToken := range request.Blinded_tokens {
		blindedToken := crypto.BlindedToken{}
		err := blindedToken.UnmarshalText([]byte(stringBlindedToken))
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Request %s: failed to unmarshal blinded tokens: %e", requestId, err))
			blindedTokenResults <- avroSchema.SigningResult{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            ERROR,
				Associated_data:   request.Associated_data,
			}
		}
		blindedTokens = append(blindedTokens, &blindedToken)
	}
	// @TODO: If one token fails they will all fail. Assess this behavior
	signedTokens, dleqProof, err := btd.ApproveTokens(blindedTokens, issuer.SigningKey)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Request %s: Could not approve new tokens: %e", requestId, err))
		blindedTokenResults <- avroSchema.SigningResult{
			Signed_tokens:     nil,
			Issuer_public_key: "",
			Status:            ERROR,
			Associated_data:   request.Associated_data,
		}
	}
	marshaledDLEQProof, err := dleqProof.MarshalText()
	if err != nil {
		errorChannel <- batgo_handlers.WrapError(
			err,
			fmt.Sprintf(
				"Request %s: Could not marshal DLEQ proof",
				requestId,
			),
			PERMANENT,
		)
	}
	var marshaledTokens []string
	for _, token := range signedTokens {
		marshaledToken, err := token.MarshalText()
		if err != nil {
			errorChannel <- batgo_handlers.WrapError(
				err,
				fmt.Sprintf(
					"Request %s: Could not marshal new tokens to bytes",
					requestId,
				),
				PERMANENT,
			)
		}
		marshaledTokens = append(marshaledTokens, string(marshaledToken[:]))
	}
	publicKey := issuer.SigningKey.PublicKey()
	marshaledPublicKey, err := publicKey.MarshalText()
	if err != nil {
		errorChannel <- batgo_handlers.WrapError(
			err,
			fmt.Sprintf(
				"Request %s: Could not marshal signing key",
				requestId,
			),
			PERMANENT,
		)
	}
	blindedTokenResults <- avroSchema.SigningResult{
		Signed_tokens:     marshaledTokens,
		Proof:             string(marshaledDLEQProof),
		Issuer_public_key: string(marshaledPublicKey),
		Status:            OK,
		Associated_data:   request.Associated_data,
	}
}
