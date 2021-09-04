package kafka

import (
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/sirupsen/logrus"
)

func BlindedTokenIssuerHandler(
	data []byte,
	resultTopic string,
	server *server.Server,
	logger *logrus.Logger,
) {
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(data)
	if err != nil {
		logger.Errorf("Failed Avro deserialization: %e", err)
	}
	var blindedTokenResults []avroSchema.SigningResult
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_token == nil {
			logger.Error("Empty request")
			continue
		}

		if request.Issuer_cohort != 0 && request.IssuerCohort != 1 {
			logger.Error("Not supported Cohort")
			continue
		}

		issuer, appErr := server.getLatestIssuer(issuerType, request.IssuerCohort)
		if appErr != nil {
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Output:            nil,
				Issuer_public_key: nil,
				Status:            2,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, issuer.SigningKey)
		if err != nil {
			logger.Error("Could not approve new tokens")
			continue
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Output:            signedTokens,
			Issuer_public_key: issuer.SigningKey,
			Status:            0,
			Associated_data:   request.Associated_data,
		})
	}
	err = Emit(resultTopic, avroSchema.SigningResultSet{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	})
	if err != nil {
		logger.Errorf("Failed to emit results to topic %s: %e", resultTopic, err)
	}
}
