package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

/*
 RedemptionStatus is an enum that represents the redemption status of a given token.
 These values are part of a contract with downstream consumers and the value assignment
 for a given variant must never change without a change to ads-serve to accomodate.
*/
type RedemptionStatus int64

const (
	Verified RedemptionStatus = iota
	Duplicate
	Unverified
	Error
	Unknown
)

func (r RedemptionStatus) String() string {
	switch r {
	case Verified:
		return "verified"
	case Duplicate:
		return "duplicate"
	case Unverified:
		return "unverified"
	case Error:
		return "error"
	case Unknown:
		return "unknown"
	}
	return "undefined"
}

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
		return errors.New(fmt.Sprintf(
			"Request %s: Failed Avro deserialization: %e",
			tokenRedeemRequestSet.Request_id, err,
		))
	}
	defer func() {
		if recover() != nil {
			err = errors.New(fmt.Sprintf(
				"Request %s: Redeem attempt panicked",
				tokenRedeemRequestSet.Request_id,
			))
		}
	}()
	var redeemedTokenResults []avroSchema.RedeemResult
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return errors.New(fmt.Sprintf("Request %s: Data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected.", tokenRedeemRequestSet.Request_id))
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		return errors.New(fmt.Sprintf(
			"Request %s: Failed to fetch all issuers",
			tokenRedeemRequestSet.Request_id,
		))
	}
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			redemptionStatus RedemptionStatus = Unknown
			verifiedIssuer                    = &cbpServer.Issuer{}
			verifiedCohort   int32            = 0
		)
		if request.Public_key == "" {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Missing public key",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          Error,
				Associated_data: request.Associated_data,
			})
			continue
		}

		if request.Token_preimage == "" || request.Signature == "" || request.Binding == "" {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Empty request",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          Error,
				Associated_data: request.Associated_data,
			})
			continue
		}

		tokenPreimage := crypto.TokenPreimage{}
		err = tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		if err != nil {
			message := fmt.Sprintf(
				"Request %s: Could not unmarshal text into preimage",
				tokenRedeemRequestSet.Request_id,
			)
			logger.Error().Err(err).Msg(message)
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   -1,
				Status:          Unverified,
				Associated_data: request.Associated_data,
			})
			continue
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		if err != nil {
			message := fmt.Sprintf("Request %s: Could not unmarshal text into verification signature", tokenRedeemRequestSet.Request_id)
			logger.Error().Err(err).Msg(message)
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   -1,
				Status:          Unverified,
				Associated_data: request.Associated_data,
			})
			continue
		}
		if redemptionStatus == Unknown {
			for _, issuer := range *issuers {
				if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
					continue
				}
				// Only attempt token verification with the issuer that was provided.
				issuerPublicKey := issuer.SigningKey.PublicKey()
				marshaledPublicKey, err := issuerPublicKey.MarshalText()
				if err != nil {
					return errors.New(fmt.Sprintf(
						"Request %s: Could not unmarshal issuer public key into text: %e",
						tokenRedeemRequestSet.Request_id,
						err,
					))
				}
				logger.Trace().Msg(fmt.Sprintf(
					"Request %s: Issuer: %s, Request: %s",
					tokenRedeemRequestSet.Request_id,
					string(marshaledPublicKey),
					request.Public_key,
				))
				if string(marshaledPublicKey) == request.Public_key {
					if err := btd.VerifyTokenRedemption(
						&tokenPreimage,
						&verificationSignature,
						string(request.Binding),
						[]*crypto.SigningKey{issuer.SigningKey},
					); err != nil {
						redemptionStatus = Unverified
					} else {
						redemptionStatus = Verified
						verifiedIssuer = &issuer
						verifiedCohort = int32(issuer.IssuerCohort)
						break
					}
				}
			}
		}

		if !redemptionStatus == Verified {
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Could not verify that the token redemption is valid",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          Unverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			logger.Trace().Msg(fmt.Sprintf(
				"Request %s: Validated",
				tokenRedeemRequestSet.Request_id,
			))
		}
		if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, string(request.Binding)); err != nil {
			logger.Error().Err(err).Msg(fmt.Sprintf(
				"Request %s: Token redemption failed: %e",
				tokenRedeemRequestSet.Request_id,
				err,
			))
			if strings.Contains(err.Error(), "Duplicate") {
				logger.Error().Msg(fmt.Sprintf(
					"Request %s: Duplicate redemption: %e",
					tokenRedeemRequestSet.Request_id,
					err,
				))
				redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
					Issuer_name:     "",
					Issuer_cohort:   0,
					Status:          DUPLICATE_REDEMPTION,
					Associated_data: request.Associated_data,
				})
			}
			logger.Error().Msg(fmt.Sprintf(
				"Request %s: Could not mark token redemption",
				tokenRedeemRequestSet.Request_id,
			))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          Error,
				Associated_data: request.Associated_data,
			})
			continue
		}
		logger.Trace().Msg(fmt.Sprintf(
			"Request %s: Redeemed",
			tokenRedeemRequestSet.Request_id,
		))
		issuerName := verifiedIssuer.IssuerType
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_name:     issuerName,
			Issuer_cohort:   verifiedCohort,
			Status:          redemptionStatus,
			Associated_data: request.Associated_data,
		})
	}
	resultSet := avroSchema.RedeemResultSet{
		Request_id: tokenRedeemRequestSet.Request_id,
		Data:       redeemedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		return errors.New(fmt.Sprintf(
			"Request %s: Failed to serialize ResultSet: %e",
			tokenRedeemRequestSet.Request_id,
			err,
		))
	}

	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		return errors.New(fmt.Sprintf(
			"Request %s: Failed to emit results to topic %s: %e",
			tokenRedeemRequestSet.Request_id,
			producer.Topic,
			err,
		))
	}
	return nil
}
