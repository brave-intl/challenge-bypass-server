package integrationtest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	batgo_kafka "github.com/brave-intl/bat-go/libs/kafka"
	"github.com/brave-intl/bat-go/libs/middleware"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/brave-intl/challenge-bypass-server/utils/test"
	"github.com/go-chi/chi"
	uuid "github.com/satori/go.uuid"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type ServerTestSuite struct {
	suite.Suite
	handler     http.Handler
	accessToken string
	srv         *server.Server
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) SetupSuite() {
	err := os.Setenv("ENV", "localtest")
	suite.Require().NoError(err)

	suite.accessToken = uuid.NewV4().String()
	middleware.TokenList = []string{suite.accessToken}

	suite.srv = &server.Server{}

	err = suite.srv.InitDbConfig()
	suite.Require().NoError(err, "Failed to setup db conn")

	suite.handler = chi.ServerBaseContext(suite.srv.SetupRouter(server.SetupLogger(context.Background())))

	suite.srv.InitDb()
	suite.srv.InitDynamo()

	err = test.SetupDynamodbTables(suite.srv.Dynamo)
	suite.Require().NoError(err)

	suite.handler = chi.ServerBaseContext(suite.srv.SetupRouter(server.SetupLogger(context.Background())))
}

func (suite *ServerTestSuite) SetupTest() {
	tables := []string{"v3_issuer_keys", "v3_issuers", "redemptions"}

	for _, table := range tables {
		_, err := suite.srv.Db.Exec("delete from " + table)
		suite.Require().NoError(err, "Failed to get clean table")
	}
}

func (suite *ServerTestSuite) TestPing() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()
	resp, err := http.Get(server.URL)
	suite.Require().NoError(err, "Ping request must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	expected := "."
	actual, err := ioutil.ReadAll(resp.Body)
	suite.Assert().NoError(err, "Reading response body should succeed")
	suite.Assert().Equal(expected, string(actual), "Message should match")
}

func (suite *ServerTestSuite) TestE2ESignAndRedeemV3() {
	ctx := context.Background()

	var issuerType = test.RandomString()
	issuer := server.Issuer{
		Version:      3,
		IssuerType:   issuerType,
		IssuerCohort: 1,
		MaxTokens:    10,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Buffer:       2,
		Overlap:      2,
		Duration:     ptr.FromString("PT10S"), // 10 Seconds
		ValidFrom:    ptr.FromTime(time.Now()),
	}

	err := suite.srv.CreateV3Issuer(issuer)
	suite.Require().NoError(err)

	// Setup Kafka
	signedTopic := uuid.NewV4().String()
	brokers, dialer := setupKafka(ctx, suite.T(), signedTopic)
	suite.Require().NoError(err)

	kafkaWriter := kafkago.NewWriter(kafkago.WriterConfig{
		Brokers: []string{brokers},
		Topic:   signedTopic,
		Dialer:  dialer,
	})

	// Create Kafka message

	tokens := make([]string, 6)
	for i := 0; i < len(tokens); i++ {
		token, err := crypto.RandomToken()
		suite.Require().NoError(err)

		blindedToken := token.Blind()
		suite.Require().NoError(err, "Must be able to blind token")

		b, err := blindedToken.MarshalText()
		suite.Require().NoError(err)

		tokens[i] = string(b)
	}

	signingRequest := avroSchema.SigningRequestSet{
		Request_id: uuid.NewV4().String(),
		Data: []avroSchema.SigningRequest{
			{
				Associated_data: nil,
				Blinded_tokens:  tokens,
				Issuer_type:     issuer.IssuerType,
				Issuer_cohort:   int32(issuer.IssuerCohort),
			},
		},
	}

	data, err := json.Marshal(signingRequest)
	suite.Require().NoError(err)

	// Process the signing request using kafka handler

	err = kafka.SignedBlindedTokenIssuerHandler(data, kafkaWriter, suite.srv, nil)
	suite.Require().NoError(err)

	// Redeem Tokens

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Read Kafka Signed Response
	kafkaReader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers: []string{brokers},
		GroupID: uuid.NewV4().String(),
		Topic:   signedTopic,
		Dialer:  dialer,
	})

	msg, err := kafkaReader.FetchMessage(ctx)
	suite.Require().NoError(err)

	signingResultSet, err := avroSchema.DeserializeSigningResultV2Set(bytes.NewReader(msg.Value))
	suite.Require().NoError(err)

	fmt.Println("result set ", signingResultSet)

	for _, data := range signingResultSet.Data {
		fmt.Println("Signed Data ", data)
	}

	//payload := fmt.Sprintf(`{"t":"%s", "signature":"%s", "payload":"%s"}`, preimageText, sigText, msg)
	//
	//redeemURL := fmt.Sprintf("%s/v3/blindedToken/%s/redemption/", server.URL, issuerType)
	//
	//response, err := suite.request(http.MethodPost, redeemURL, bytes.NewBuffer([]byte(payload)))
	//suite.Require().NoError(err)
	//
	//suite.Require().Equal(http.StatusOK, response.StatusCode)
}

// setupKafka is a test helper to setup kafka brokers and topic
func setupKafka(ctx context.Context, t *testing.T, topics ...string) (string, *kafkago.Dialer) {
	kafkaBrokers := strings.Split(os.Getenv("KAFKA_BROKERS"), ",")[0]
	dialer, _, err := batgo_kafka.TLSDialer()
	assert.NoError(t, err)

	for _, topic := range topics {
		conn, err := dialer.DialLeader(ctx, "tcp", kafkaBrokers, topic, 0)
		assert.NoError(t, err)

		err = conn.CreateTopics(kafkago.TopicConfig{Topic: topic, NumPartitions: 1, ReplicationFactor: 1})
		assert.NoError(t, err)
	}

	return kafkaBrokers, dialer
}
