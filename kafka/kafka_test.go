package kafka

import (
	"bufio"
	"bytes"
	"testing"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type KafkaTestSuite struct {
	suite.Suite
}

func (suite *KafkaTestSuite) TestSignAndRedemptionRoundTrip() {
	type tokenRef struct {
		token        *crypto.Token
		blindedToken *crypto.BlindedToken
	}

	tokenLookup := map[string]tokenRef{}
	blindedTokens := []string{}

	for i := 0; i < 8; i++ {
		token, err := crypto.RandomToken()
		require.NoError(suite.T(), err)

		blindedToken := token.Blind()
		blindedTokenBytes, err := blindedToken.MarshalText()
		require.NoError(suite.T(), err)
		blindedTokenStr := string(blindedTokenBytes)

		tokenLookup[blindedTokenStr] = tokenRef{token, blindedToken}
		blindedTokens = append(blindedTokens, blindedTokenStr)
	}

	signingRequest := avroSchema.SigningRequestSet{
		Request_id: "a976f6ec-219a-11ee-bdc6-00155d0da3ed",
		Data: []avroSchema.SigningRequest{
			avroSchema.SigningRequest{
				Associated_data: []byte("{}"),
				Blinded_tokens:  blindedTokens,
				Issuer_type:     "view",
				Issuer_cohort:   0,
			},
		},
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err := signingRequest.Serialize(writer)
	require.NoError(suite.T(), err)

	err = writer.Flush()
	require.NoError(suite.T(), err)

	message := kafka.Message{
		Topic: "signing-request",
		Value: buf.Bytes(),
	}

	mockWriter := new(MockKafkaWriter)
	mockSrv := new(server.MockServer)
	mockLogger := zerolog.Nop()

	mockIssuer := suite.makeIssuer()

	mockSrv.
		On(
			"GetLatestIssuerKafka",
			signingRequest.Data[0].Issuer_type,
			int16(signingRequest.Data[0].Issuer_cohort),
		).
		Return(mockIssuer, nil).
		Once()

	mockWriter.
		On("Topic").
		Return("signing-response").
		Once()

	mockWriter.
		On(
			"WriteMessages",
			mock.Anything,
			mock.Anything,
		).
		Run(func(args mock.Arguments) {
			messages, ok := args.Get(1).([]kafka.Message)
			require.True(suite.T(), ok)
			require.Equal(suite.T(), 1, len(messages))

			message := messages[0].Value
			res, err := avroSchema.DeserializeSigningResultV2Set(bytes.NewReader(message))
			require.NoError(suite.T(), err)

			for _, result := range res.Data {
				signedToken := &crypto.SignedToken{}
				err = signedToken.UnmarshalText([]byte(result.Signed_tokens[0]))
				require.NoError(suite.T(), err)

				ref, ok := tokenLookup[result.Blinded_tokens[0]]
				require.True(suite.T(), ok)

				var signingKey *crypto.SigningKey
				for _, issuerKey := range mockIssuer.Keys {
					if *issuerKey.PublicKey == result.Issuer_public_key {
						signingKey = issuerKey.SigningKey
					}
				}
				require.NotNil(suite.T(), signingKey)

				publicKey := &crypto.PublicKey{}
				err = publicKey.UnmarshalText([]byte(result.Issuer_public_key))
				require.NoError(suite.T(), err)

				proof, err := crypto.NewBatchDLEQProof(
					[]*crypto.BlindedToken{ref.blindedToken},
					[]*crypto.SignedToken{signedToken},
					signingKey,
				)
				require.NoError(suite.T(), err)

				unblindedToken, err := proof.VerifyAndUnblind(
					[]*crypto.Token{ref.token},
					[]*crypto.BlindedToken{ref.blindedToken},
					[]*crypto.SignedToken{signedToken},
					publicKey,
				)
				require.NoError(suite.T(), err)
				require.GreaterOrEqual(suite.T(), 1, len(unblindedToken))

				bindingStr := "The quick brown fox jumps over the lazy dog"

				verificationKey := unblindedToken[0].DeriveVerificationKey()
				verificationSignature, err := verificationKey.Sign(bindingStr)
				require.NoError(suite.T(), err)

				signatureBytes, err := verificationSignature.MarshalText()
				require.NoError(suite.T(), err)
				signatureStr := string(signatureBytes)

				tokenPreimage := unblindedToken[0].Preimage()
				tokenPreimageBytes, err := tokenPreimage.MarshalText()
				require.NoError(suite.T(), err)
				tokenPreimageStr := string(tokenPreimageBytes)

				redeemRequestSet := avroSchema.RedeemRequestSet{
					Request_id: "de72b94e-a624-40f9-ba9f-c9d32156548e",
					Data: []avroSchema.RedeemRequest{
						avroSchema.RedeemRequest{
							Associated_data: []byte("{}"),
							Public_key:      result.Issuer_public_key,
							Token_preimage:  tokenPreimageStr,
							Binding:         bindingStr,
							Signature:       signatureStr,
						},
					},
				}

				var buf bytes.Buffer
				writer := bufio.NewWriter(&buf)
				err = redeemRequestSet.Serialize(writer)
				require.NoError(suite.T(), err)

				err = writer.Flush()
				require.NoError(suite.T(), err)

				message := kafka.Message{
					Topic: "redeem-request",
					Value: buf.Bytes(),
				}

				mockWriter := new(MockKafkaWriter)
				mockSrv := new(server.MockServer)
				mockLogger := zerolog.Nop()

				mockSrv.On("FetchAllIssuers").
					Return(&[]server.Issuer{*mockIssuer}, nil).
					Once()

				mockRedemption := &server.RedemptionV2{}
				mockSrv.On(
					"CheckRedeemedTokenEquivalence",
					mock.Anything,
					mock.Anything,
					mock.Anything).
					Return(mockRedemption, server.NoEquivalence, nil).
					Once()

				mockSrv.On("PersistRedemption", mock.Anything).Return(nil).Once()

				mockWriter.On("Topic").Return("redeem-request").Once()
				mockWriter.On(
					"WriteMessages",
					mock.Anything,
					mock.Anything).
					Run(func(args mock.Arguments) {
						messages, ok := args.Get(1).([]kafka.Message)
						require.True(suite.T(), ok)
						require.Equal(suite.T(), 1, len(messages))

						message := messages[0].Value
						_, err := avroSchema.DeserializeRedeemResultSet(bytes.NewReader(message))
						require.NoError(suite.T(), err)
					}).
					Return(nil).
					Once()

				err = SignedTokenRedeemHandler(
					message,
					mockWriter,
					mockSrv,
					&mockLogger,
				)

				require.NoError(suite.T(), err)
			}
		}).
		Return(nil).
		Once()

	err = SignedBlindedTokenIssuerHandler(
		message,
		mockWriter,
		mockSrv,
		&mockLogger,
	)

	require.NoError(suite.T(), err)
}

/*
func (suite *KafkaTestSuite) TestSignedTokenRedeemHandler() {

	mockIssuer := suite.makeIssuer()
	redeemRequest := avroSchema.RedeemRequestSet{
		Request_id: "de72b94e-a624-40f9-ba9f-c9d32156548e",
		Data: []avroSchema.RedeemRequest{
			avroSchema.RedeemRequest{
				Associated_data: []byte("{\"confirmation\":{\"id\":\"de72b94e-a624-40f9-ba9f-c9d32156548e\",\"creativeInstanceId\":\"7e310987-0a02-46a4-86dc-262230dedb39\",\"createdAt\":\"2023-08-17T16:39:32.778Z\",\"modifiedAt\":\"2023-08-17T16:39:32.778Z\",\"type\":\"dismiss\",\"price\":0,\"clientPrice\":0,\"blindedPaymentToken\":\"XDoYrV1JWSLMexI+fEGj0qL6Bt5LuAWYIC8YCDMQCAw=\",\"payload\":{},\"country\":\"IN\",\"platform\":\"windows\",\"buildChannel\":\"beta\",\"flagged\":false,\"tags\":{\"fraud\":[],\"CV\":\"116.0.0.0\",\"via\":0,\"version\":\"v3\",\"host\":\"anonymous.ads.bravesoftware.com\",\"rate-limited\":0,\"datacenter\":0,\"vpn\":0,\"inGeoTarget\":1,\"onTime\":1,\"rotatingHashCounter\":1},\"os\":\"windows\",\"browserProvidedDetails\":{\"catalog\":[{\"id\":\"80d2ba79e827a2f068abb59b267c84e2c1f40012\"}],\"createdAtTimestamp\":\"2023-08-17T16:00:00.000Z\",\"platform\":\"windows\",\"publicKey\":\"wgMhKwj/Vs832efOg+RlqJvLy3Ta3UDbz1wV+Z+dzEU=\",\"rotating_hash\":\"AOULvIoDfV6oL+y1UownA89drOK6nvG4DUiCNDQM5BE=\",\"segment\":\"untargeted\",\"systemTimestamp\":\"2023-08-17T16:00:00.000Z\",\"versionNumber\":\"116.0.5845.96\"},\"credential\":{\"signature\":\"IaACtriyTr/lSv6h8ZG3+OHnxzMp9lq7NRYRoiva9v52UyE58CAey2r7zmd/Iz4YK4Ye6MHtpFaMR8UC4Jv7Pg==\",\"t\":\"j+9IGQm4C7Ub/o9k617RcKO+UfT6OqQP8oCACWzik3rtRTebXC2zT0PVjCeMBnuz7rm8Qk/JxvP4DVH7M6QleQ==\",\"payload\":\"{\\\"blindedPaymentTokens\\\":[\\\"XDoYrV1JWSLMexI+fEGj0qL6Bt5LuAWYIC8YCDMQCAw=\\\"],\\\"buildChannel\\\":\\\"beta\\\",\\\"catalog\\\":[{\\\"id\\\":\\\"80d2ba79e827a2f068abb59b267c84e2c1f40012\\\"}],\\\"createdAtTimestamp\\\":\\\"2023-08-17T16:00:00.000Z\\\",\\\"creativeInstanceId\\\":\\\"7e310987-0a02-46a4-86dc-262230dedb39\\\",\\\"platform\\\":\\\"windows\\\",\\\"publicKey\\\":\\\"wgMhKwj/Vs832efOg+RlqJvLy3Ta3UDbz1wV+Z+dzEU=\\\",\\\"rotating_hash\\\":\\\"AOULvIoDfV6oL+y1UownA89drOK6nvG4DUiCNDQM5BE=\\\",\\\"segment\\\":\\\"untargeted\\\",\\\"studies\\\":[{\\\"group\\\":\\\"DefaultAdNotificationsPerHour=10/MaximumAdNotificationsPerDay=100/MaximumInlineContentAdsPerHour=6/MaximumInlineContentAdsPerDay=20/AdServingVersion=2\\\",\\\"name\\\":\\\"BraveAds.AdServingStudy\\\"}],\\\"systemTimestamp\\\":\\\"2023-08-17T16:00:00.000Z\\\",\\\"transactionId\\\":\\\"de72b94e-a624-40f9-ba9f-c9d32156548e\\\",\\\"type\\\":\\\"dismiss\\\",\\\"versionNumber\\\":\\\"116.0.5845.96\\\"}\"},\"confirmationRedeemState\":\"pending\"},\"redemption_type\":\"confirmation\"}"),
				Public_key:      "wgMhKwj/Vs832efOg+RlqJvLy3Ta3UDbz1wV+Z+dzEU=",
				Token_preimage:  "j+9IGQm4C7Ub/o9k617RcKO+UfT6OqQP8oCACWzik3rtRTebXC2zT0PVjCeMBnuz7rm8Qk/JxvP4DVH7M6QleQ==",
				Binding:         "{\"blindedPaymentTokens\":[\"XDoYrV1JWSLMexI+fEGj0qL6Bt5LuAWYIC8YCDMQCAw=\"],\"buildChannel\":\"beta\",\"catalog\":[{\"id\":\"80d2ba79e827a2f068abb59b267c84e2c1f40012\"}],\"createdAtTimestamp\":\"2023-08-17T16:00:00.000Z\",\"creativeInstanceId\":\"7e310987-0a02-46a4-86dc-262230dedb39\",\"platform\":\"windows\",\"publicKey\":\"wgMhKwj/Vs832efOg+RlqJvLy3Ta3UDbz1wV+Z+dzEU=\",\"rotating_hash\":\"AOULvIoDfV6oL+y1UownA89drOK6nvG4DUiCNDQM5BE=\",\"segment\":\"untargeted\",\"studies\":[{\"group\":\"DefaultAdNotificationsPerHour=10/MaximumAdNotificationsPerDay=100/MaximumInlineContentAdsPerHour=6/MaximumInlineContentAdsPerDay=20/AdServingVersion=2\",\"name\":\"BraveAds.AdServingStudy\"}],\"systemTimestamp\":\"2023-08-17T16:00:00.000Z\",\"transactionId\":\"de72b94e-a624-40f9-ba9f-c9d32156548e\",\"type\":\"dismiss\",\"versionNumber\":\"116.0.5845.96\"}",
				Signature:       "IaACtriyTr/lSv6h8ZG3+OHnxzMp9lq7NRYRoiva9v52UyE58CAey2r7zmd/Iz4YK4Ye6MHtpFaMR8UC4Jv7Pg==",
			},
		},
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err := redeemRequest.Serialize(writer)
	require.NoError(suite.T(), err)

	err = writer.Flush()
	require.NoError(suite.T(), err)

	message := kafka.Message{
		Topic: "redeem-request",
		Value: buf.Bytes(),
	}

	mockWriter := new(MockKafkaWriter)
	mockSrv := new(server.MockServer)
	mockLogger := zerolog.Nop()

	mockSrv.On("FetchAllIssuers").
		Return(&[]server.Issuer{*mockIssuer}, nil).
		Once()

	mockWriter.On("Topic").Return("redeem-request").Once()
	mockWriter.On(
		"WriteMessages",
		mock.Anything,
		mock.Anything).
		Run(func(args mock.Arguments) {
			messages := args.Get(1).([]kafka.Message)
			require.Equal(suite.T(), 1, len(messages))

			message := messages[0].Value
			res, err := avroSchema.DeserializeRedeemResult(bytes.NewReader(message))
			require.NoError(suite.T(), err)

			fmt.Printf("%+v\n", res)
			require.True(suite.T(), false)
		}).
		Return(nil).
		Once()

	err = SignedTokenRedeemHandler(
		message,
		mockWriter,
		mockSrv,
		&mockLogger,
	)

	require.NoError(suite.T(), err)
}
*/

func TestKafkaTestSuite(t *testing.T) {
	suite.Run(t, new(KafkaTestSuite))
}

func (suite *KafkaTestSuite) makeIssuer() *server.Issuer {
	duration := "30"
	now := time.Now()

	issuerID, err := uuid.Parse("a59dedd6-2029-11ee-ba60-00155d0da3ed")
	require.NoError(suite.T(), err)

	issuer := server.Issuer{
		SigningKey:   nil,
		ID:           &issuerID,
		IssuerType:   "0.001BAT_0",
		IssuerCohort: 0,
		MaxTokens:    40,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Duration(37) * (time.Hour * 24)),
		RotatedAt:    now.Add(time.Duration(30) * (time.Hour * 24)),
		Version:      3,
		ValidFrom:    &now,
		Buffer:       1,
		Overlap:      7,
		Duration:     &duration,
		Keys:         []server.IssuerKeys{},
	}

	for i := 0; i < issuer.Buffer+issuer.Overlap; i++ {
		issuer.Keys = append(issuer.Keys, suite.makeIssuerKey(issuer))
	}

	return &issuer
}

func (suite *KafkaTestSuite) makeIssuerKey(issuer server.Issuer) server.IssuerKeys {
	now := time.Now()

	signingKey, err := crypto.RandomSigningKey()
	require.NoError(suite.T(), err)

	signingKeyText, err := signingKey.MarshalText()
	require.NoError(suite.T(), err)

	pubkeyText, err := signingKey.PublicKey().MarshalText()
	require.NoError(suite.T(), err)

	keyID, err := uuid.Parse("e16bebae-202b-11ee-bf8a-00155d0da3ed")
	require.NoError(suite.T(), err)

	issuerSigningKey := &crypto.SigningKey{}
	err = issuerSigningKey.UnmarshalText(signingKeyText)
	require.NoError(suite.T(), err)

	startAt := now.Add(time.Duration(1) * -1 * time.Hour)
	endAt := now.Add(time.Duration(1) * 1 * time.Hour)

	issuerKey := server.IssuerKeys{
		SigningKey: issuerSigningKey,
		ID:         &keyID,
		PublicKey:  ptr.FromString(string(pubkeyText)),
		Cohort:     issuer.IssuerCohort,
		IssuerID:   issuer.ID,
		CreatedAt:  &now,
		StartAt:    &startAt,
		EndAt:      &endAt,
	}

	return issuerKey
}
