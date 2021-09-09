package kafka

import (
	"bytes"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/sirupsen/logrus"
	"strings"
)

func BlindedTokenIssuerHandler(
	data []byte,
	resultTopic string,
	server *server.Server,
	logger *logrus.Logger,
) {
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		logger.Errorf("Failed Avro deserialization: %e", err)
	}
	var blindedTokenResults []avroSchema.SigningResult
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_token == nil {
			logger.Error("Empty request")
			continue
		}

		if request.Issuer_cohort != 0 && request.Issuer_cohort != 1 {
			logger.Error("Provided cohort is not supported: %d", request.Issuer_cohort)
			continue
		}

		issuer, appErr := server.GetLatestIssuer(request.Issuer_type, int(request.Issuer_cohort))
		if appErr != nil {
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Output:            nil,
				Issuer_public_key: nil,
				Status:            2,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		blindedToken := crypto.BlindedToken{}
		blindedToken.UnmarshalText(request.Blinded_token)
		blindedTokens := []*crypto.BlindedToken{&blindedToken}
		// @TODO: If one token fails they will all fail. Assess this behavior
		signedTokens, _, err := btd.ApproveTokens(blindedTokens, issuer.SigningKey)
		if err != nil {
			logger.Error("Could not approve new tokens: %e", err)
			continue
		}
		var marshaledTokens []string
		for _, token := range signedTokens {
			marshaledToken, err := token.MarshalText()
			if err != nil {
				logger.Error("Could not marshal new tokens to bytes: %e", err)
				panic("Could not marshal new tokens to bytes")
				//continue
			}
			marshaledTokens = append(marshaledTokens, string(marshaledToken[:]))
		}
		marshaledSigningKey, err := issuer.SigningKey.MarshalText()
		if err != nil {
			logger.Error("Could not marshal signing key: %e", err)
			panic("Could not marshal signing key")
			//continue
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Output:            []byte(strings.Join(marshaledTokens, ",")),
			Issuer_public_key: marshaledSigningKey,
			Status:            0,
			Associated_data:   utils.StructToBytes(request.Associated_data),
		})
	}
	err = Emit(resultTopic, utils.StructToBytes(avroSchema.SigningResultSet{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}), logger)
	if err != nil {
		logger.Errorf("Failed to emit results to topic %s: %e", resultTopic, err)
	}
}
