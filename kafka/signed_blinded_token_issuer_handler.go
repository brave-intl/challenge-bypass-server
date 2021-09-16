package kafka

import (
	"bytes"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/sirupsen/logrus"
)

/*
 BlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
 @TODO: It would be better for the Server implementation and the Kafka implementation of
 this behavior to share utility functions rather than passing an instance of the server
 as an argument here. That will require a bit of refactoring.
*/
func SignedBlindedTokenIssuerHandler(
	data []byte,
	resultTopic string,
	server *cbpServer.Server,
	logger *logrus.Logger,
) {
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		logger.Errorf("Failed Avro deserialization: %e", err)
	}
	var blindedTokenResults []avroSchema.SigningResult
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_tokens == nil {
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
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            2,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			blindedToken := crypto.BlindedToken{}
			blindedToken.UnmarshalText([]byte(stringBlindedToken))
			blindedTokens = append(blindedTokens, &blindedToken)
		}
		// @TODO: If one token fails they will all fail. Assess this behavior
		signedTokens, dleqProof, err := btd.ApproveTokens(blindedTokens, issuer.SigningKey)
		if err != nil {
			logger.Error("Could not approve new tokens: %e", err)
			continue
		}
		marshaledDLEQProof, err := dleqProof.MarshalText()
		if err != nil {
			logger.Error("Could not marshal DLEQ proof: %e", err)
			panic("Could not marshal DLEQ proof")
		}
		var marshaledTokens []string
		for _, token := range signedTokens {
			marshaledToken, err := token.MarshalText()
			if err != nil {
				logger.Error("Could not marshal new tokens to bytes: %e", err)
				panic("Could not marshal new tokens to bytes")
			}
			marshaledTokens = append(marshaledTokens, string(marshaledToken[:]))
		}
		publicKey := issuer.SigningKey.PublicKey()
		marshaledPublicKey, err := publicKey.MarshalText()
		if err != nil {
			logger.Error("Could not marshal signing key: %e", err)
			panic("Could not marshal signing key")
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Signed_tokens:     marshaledTokens,
			Proof:             string(marshaledDLEQProof),
			Issuer_public_key: string(marshaledPublicKey),
			Status:            0,
			Associated_data:   request.Associated_data,
		})
	}
	resultSet := avroSchema.SigningResultSet{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		logger.Errorf("Failed to serialize ResultSet: %s", resultSet)
	}
	err = Emit(resultTopic, resultSetBuffer.Bytes(), logger)
	if err != nil {
		logger.Errorf("Failed to emit results to topic %s: %e", resultTopic, err)
	}
}
