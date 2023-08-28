package kafka

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
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

	for i := 0; i < 1; i++ {
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
				Issuer_type:     "0.001BAT_0",
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

	srv := &server.Server{
		Logger: logrus.New(),
	}
	dbConfig := server.DBConfig{
		ConnectionURI:    "postgres://btokens:password@postgres:5432/postgres?sslmode=disable",
		DynamodbEndpoint: "http://localhost:8080",
	}
	srv.LoadDBConfig(dbConfig)
	srv.InitDB()
	srv.InitDynamo()

	mockLogger := zerolog.Nop()
	mockIssuer := suite.makeIssuer()
	mockIssuer.Keys = nil

	err = srv.CreateV3Issuer(*mockIssuer)
	require.NoError(suite.T(), err)

	s, e := json.MarshalIndent(mockIssuer, "", "\t")
	require.NoError(suite.T(), e)
	fmt.Println(string(s))

	mockIssuers, err := srv.FetchAllIssuers()
	require.NoError(suite.T(), err)
	require.True(suite.T(), len(mockIssuers) == 1)

	mockIssuer = &mockIssuers[0]

	s, e = json.MarshalIndent(mockIssuer, "", "\t")
	require.NoError(suite.T(), e)
	fmt.Println(string(s))

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
				require.Equal(suite.T(), len(blindedTokens), len(result.Signed_tokens))
				err = signedToken.UnmarshalText([]byte(result.Signed_tokens[0]))
				require.NoError(suite.T(), err)

				ref, ok := tokenLookup[result.Blinded_tokens[0]]
				require.True(suite.T(), ok)

				s, e := json.MarshalIndent(mockIssuer, "", "\t")
				require.NoError(suite.T(), e)
				fmt.Println(string(s))

				var signingKeyBytes []byte
				for _, issuerKey := range mockIssuer.Keys {
					if *issuerKey.PublicKey == result.Issuer_public_key {
						signingKeyBytes = issuerKey.SigningKey
					}
				}
				require.NotNil(suite.T(), signingKeyBytes)
				require.True(suite.T(), len(signingKeyBytes) > 0)

				signingKey := &crypto.SigningKey{}
				err = signingKey.UnmarshalText(signingKeyBytes)
				require.NoError(suite.T(), err)

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
				mockLogger := zerolog.Nop()

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
					srv,
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
		srv,
		&mockLogger,
	)

	require.NoError(suite.T(), err)
}

func TestKafkaTestSuite(t *testing.T) {
	suite.Run(t, new(KafkaTestSuite))
}

func (suite *KafkaTestSuite) makeIssuer() *model.Issuer {
	duration := "P1M"
	now := time.Now()

	issuerID, err := uuid.Parse("a59dedd6-2029-11ee-ba60-00155d0da3ed")
	require.NoError(suite.T(), err)

	issuer := model.Issuer{
		SigningKey:   nil,
		ID:           &issuerID,
		IssuerType:   "0.001BAT_0",
		IssuerCohort: 0,
		MaxTokens:    40,
		CreatedAt:    pq.NullTime{Time: now, Valid: true},
		ExpiresAt:    pq.NullTime{Time: now.Add(time.Duration(37) * (time.Hour * 24)), Valid: true},
		RotatedAt:    pq.NullTime{Time: now.Add(time.Duration(30) * (time.Hour * 24)), Valid: true},
		Version:      3,
		ValidFrom:    &now,
		Buffer:       1,
		Overlap:      0,
		Duration:     &duration,
		Keys:         []model.IssuerKeys{},
	}

	for i := 0; i < issuer.Buffer+issuer.Overlap; i++ {
		issuer.Keys = append(issuer.Keys, suite.makeIssuerKey(issuer))
	}

	return &issuer
}

func (suite *KafkaTestSuite) makeIssuerKey(issuer model.Issuer) model.IssuerKeys {
	now := time.Now()

	signingKey, err := crypto.RandomSigningKey()
	require.NoError(suite.T(), err)

	signingKeyText, err := signingKey.MarshalText()
	require.NoError(suite.T(), err)

	pubkeyText, err := signingKey.PublicKey().MarshalText()
	require.NoError(suite.T(), err)

	keyID, err := uuid.Parse("e16bebae-202b-11ee-bf8a-00155d0da3ed")
	require.NoError(suite.T(), err)

	startAt := now.Add(time.Duration(1) * -1 * time.Hour)
	endAt := now.Add(time.Duration(1) * 1 * time.Hour)

	issuerKey := model.IssuerKeys{
		SigningKey: signingKeyText,
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
