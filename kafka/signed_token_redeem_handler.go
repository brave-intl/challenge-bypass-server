package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

/*
 BlindedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation
 tokens provided.
*/
func SignedTokenRedeemHandler(
	data []byte,
	producer *kafka.Writer,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) error {
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed Avro deserialization: %e", tokenRedeemRequestSet.Request_id, err))
	}
	defer func() {
		if recover() != nil {
			err = errors.New(fmt.Sprintf("Request %s: Redeem attempt panicked", tokenRedeemRequestSet.Request_id))
		}
	}()
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return errors.New(fmt.Sprintf("Request %s: Data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected.", tokenRedeemRequestSet.Request_id))
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed to fetch all issuers", tokenRedeemRequestSet.Request_id))
	}
	var wg sync.WaitGroup
	tokenRedeemResultsChannel := make(chan avroSchema.RedeemResult)
	errorSet := make(chan error)
	for _, request := range tokenRedeemRequestSet.Data {
		wg.Add(1)
		handleTokenRedeemRequest(
			wg,
			request,
			tokenRedeemRequestSet.Request_id,
			issuers,
			tokenRedeemResultsChannel,
			errorSet,
			server,
			logger,
		)
	}
	wg.Wait()

	var tokenRedeemResults []avroSchema.RedeemResult
	for tokenRedeemResult := range tokenRedeemResultsChannel {
		tokenRedeemResults = append(tokenRedeemResults, tokenRedeemResult)
	}

	resultSet := avroSchema.RedeemResultSet{
		Request_id: tokenRedeemRequestSet.Request_id,
		Data:       tokenRedeemResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed to serialize ResultSet: %e", tokenRedeemRequestSet.Request_id, err))
	}

	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed to emit results to topic %s: %e", tokenRedeemRequestSet.Request_id, producer.Topic, err))
	}
	return nil
}

func handleTokenRedeemRequest(
	wg sync.WaitGroup,
	request avroSchema.RedeemRequest,
	requestId string,
	issuers *[]cbpServer.Issuer,
	tokenRedeemResults chan avroSchema.RedeemResult,
	errorSet chan error,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) {
	defer wg.Done()
	const (
		OK                   = 0
		DUPLICATE_REDEMPTION = 1
		UNVERIFIED           = 2
		ERROR                = 3
	)
	var (
		verified             = false
		verifiedIssuer       = &cbpServer.Issuer{}
		verifiedCohort int32 = 0
	)
	if request.Public_key == "" {
		logger.Error().Msg(fmt.Sprintf("Request %s: Missing public key", requestId))
		tokenRedeemResults <- avroSchema.RedeemResult{
			Issuer_name:     "",
			Issuer_cohort:   0,
			Status:          ERROR,
			Associated_data: request.Associated_data,
		}
	}

	if request.Token_preimage == "" || request.Signature == "" || request.Binding == "" {
		logger.Error().Msg(fmt.Sprintf("Request %s: Empty request", requestId))
		tokenRedeemResults <- avroSchema.RedeemResult{
			Issuer_name:     "",
			Issuer_cohort:   0,
			Status:          ERROR,
			Associated_data: request.Associated_data,
		}
	}

	tokenPreimage := crypto.TokenPreimage{}
	err := tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
	if err != nil {
		errorSet <- errors.New(
			fmt.Sprintf(
				"Request %s: Could not unmarshal text into preimage: %e",
				requestId, err,
			),
		)
	}
	verificationSignature := crypto.VerificationSignature{}
	err = verificationSignature.UnmarshalText([]byte(request.Signature))
	if err != nil {
		errorSet <- errors.New(
			fmt.Sprintf(
				"Request %s: Could not unmarshal text into verification signature: %e",
				requestId, err,
			),
		)
	}
	for _, issuer := range *issuers {
		if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
			return
		}
		// Only attempt token verification with the issuer that was provided.
		issuerPublicKey := issuer.SigningKey.PublicKey()
		marshaledPublicKey, err := issuerPublicKey.MarshalText()
		if err != nil {
			errorSet <- errors.New(
				fmt.Sprintf(
					"Request %s: Could not unmarshal issuer public key into text: %e",
					requestId, err,
				),
			)
		}
		logger.Trace().Msg(fmt.Sprintf("Request %s: Issuer: %s, Request: %s", requestId, string(marshaledPublicKey), request.Public_key))
		if string(marshaledPublicKey) == request.Public_key {
			if err := btd.VerifyTokenRedemption(
				&tokenPreimage,
				&verificationSignature,
				string(request.Binding),
				[]*crypto.SigningKey{issuer.SigningKey},
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
		logger.Error().Msg(fmt.Sprintf("Request %s: Could not verify that the token redemption is valid", requestId))
		tokenRedeemResults <- avroSchema.RedeemResult{
			Issuer_name:     "",
			Issuer_cohort:   0,
			Status:          UNVERIFIED,
			Associated_data: request.Associated_data,
		}
	} else {
		logger.Trace().Msg(fmt.Sprintf("Request %s: Validated", requestId))
	}
	if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, string(request.Binding)); err != nil {
		logger.Error().Err(err).Msg(fmt.Sprintf("Request %s: Token redemption failed: %e", requestId, err))
		if strings.Contains(err.Error(), "Duplicate") {
			logger.Error().Msg(fmt.Sprintf("Request %s: Duplicate redemption: %e", requestId, err))
			tokenRedeemResults <- avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          DUPLICATE_REDEMPTION,
				Associated_data: request.Associated_data,
			}
		}
		logger.Error().Msg(fmt.Sprintf("Request %s: Could not mark token redemption", requestId))
		tokenRedeemResults <- avroSchema.RedeemResult{
			Issuer_name:     "",
			Issuer_cohort:   0,
			Status:          ERROR,
			Associated_data: request.Associated_data,
		}
	}
	logger.Trace().Msg(fmt.Sprintf("Request %s: Redeemed", requestId))
	issuerName := verifiedIssuer.IssuerType
	tokenRedeemResults <- avroSchema.RedeemResult{
		Issuer_name:     issuerName,
		Issuer_cohort:   verifiedCohort,
		Status:          OK,
		Associated_data: request.Associated_data,
	}
}
