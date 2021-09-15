package kafka

import (
	"bytes"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

func BlindedTokenIssuerHandler(
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
				Signed_tokens:            nil,
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

func BlindedTokenRedeemHandler(
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
		if request.Issuer_type == "" {
			logger.Error("Missing issuer type")
			continue
		}

		if request.Token_preimage == nil || request.Signature == nil || request.Token == nil {
			logger.Error("Empty request")
			continue
		}

		var verified = false
		var verifiedIssuer = &cbpServer.Issuer{}
		var verifiedCohort int32 = 0
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
				string(request.Token),
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

		if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, string(request.Token)); err != nil {
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
			Output:            []byte(request.Token),
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
