package kafka

import (
	"bytes"
	"strings"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/sirupsen/logrus"
)

/*
 BlindedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation
 tokens provided.
*/
func SignedTokenRedeemHandler(
	data []byte,
	resultTopic string,
	server *cbpServer.Server,
	logger *logrus.Logger,
) {
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		logger.Errorf("Failed Avro deserialization: %e", err)
	}
	var redeemedTokenResults []avroSchema.RedeemResult
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			verified             = false
			verifiedIssuer       = &cbpServer.Issuer{}
			verifiedCohort int32 = 0
		)
		if request.Issuer_type == "" {
			logger.Error("Missing issuer type")
			continue
		}

		if request.Token_preimage == "" || request.Signature == "" || request.Signature_source == "" {
			logger.Error("Empty request")
			continue
		}

		issuers := server.MustGetIssuers(request.Issuer_type)
		tokenPreimage := crypto.TokenPreimage{}
		err := tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		if err != nil {
			logger.Errorf("Could not unmarshal text into preimage: %e", err)
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		if err != nil {
			logger.Errorf("Could not unmarshal text into verification signature: %e", err)
		}
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}
			if err := btd.VerifyTokenRedemption(
				&tokenPreimage,
				&verificationSignature,
				string(request.Signature_source),
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

		if !verified {
			logger.Error("Could not verify that the token redemption is valid")
		}
		if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, string(request.Signature_source)); err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				logger.Error(err)
			}
			logger.Error("Could not mark token redemption")
		}
		if err != nil {
			logger.Error("Could not encode the blinded token")
			panic(err)
		}
		publicKey := verifiedIssuer.SigningKey.PublicKey()
		marshaledPublicKey, err := publicKey.MarshalText()
		if err != nil {
			logger.Error("Could not marshal public key text")
			panic(err)
		}
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_public_key: string(marshaledPublicKey),
			Issuer_cohort:     verifiedCohort,
			Status:            0,
			Associated_data:   request.Associated_data,
		})
	}
	resultSet := avroSchema.RedeemResultSet{
		Request_id: tokenRedeemRequestSet.Request_id,
		Data:       redeemedTokenResults,
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
