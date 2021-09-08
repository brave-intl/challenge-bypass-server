package kafka

import (
	"bytes"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/sirupsen/logrus"
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

		if request.Issuer_cohort != "0" && request.Issuer_cohort != "1" {
			logger.Error("Not supported Cohort")
			continue
		}

		issuer, appErr := server.GetLatestIssuer(request.Issuer_type /*, request.Issuer_cohort*/)
		if appErr != nil {
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Output:            nil,
				Issuer_public_key: nil,
				Status:            2,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		blinded_tokens := []*crypto.BlindedToken{&crypto.BlindedToken{
			raw: request.Blinded_token,
		}}
		signedTokens, proof, err := btd.ApproveTokens(blinded_tokens, issuer.SigningKey)
		if err != nil {
			logger.Error("Could not approve new tokens")
			continue
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Output:            utils.StructToBytes(signedTokens),
			Issuer_public_key: utils.StructToBytes(issuer.SigningKey),
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
