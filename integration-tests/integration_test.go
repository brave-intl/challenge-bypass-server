//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/google/uuid"
	kafka "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/utils/test"
)

type RedeemEndpoint string

const (
	RedeemV1             RedeemEndpoint = "v1"
	RedeemV3             RedeemEndpoint = "v3"
	kafkaHost                           = "kafka:9092"
	maxRetries                          = 10
	retryInterval                       = 2 * time.Second
	responseWaitDuration                = 30 * time.Second
)

var (
	connectionTestTopicName   = "test.connection." + uuid.New().String()
	requestRedeemTopicName    = os.Getenv("TEST_SHOULD_WRITE_REDEEM_REQUESTS_HERE")
	responseRedeemTopicName   = os.Getenv("TEST_SHOULD_READ_REDEEM_REQUESTS_HERE")
	requestIssuanceTopicName  = os.Getenv("TEST_SHOULD_WRITE_SIGNING_REQUESTS_HERE")
	responseIssuanceTopicName = os.Getenv("TEST_SHOULD_READ_SIGNING_REQUESTS_HERE")
)

type tokenInfo struct {
	UnblindedToken *crypto.UnblindedToken
	SignedKey      string
}

type issuerResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Cohort    int32             `json:"cohort"`
}

type issuerV3CreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int32      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
	ValidFrom *time.Time `json:"valid_from"`
	Duration  string     `json:"duration"`
	Overlap   int        `json:"overlap"`
	Buffer    int        `json:"buffer"`
}

type blindedTokenRedeemRequest struct {
	Payload       string                        `json:"payload"`
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
}

func TestMain(m *testing.M) {
	setup()
	result := m.Run()
	os.Exit(result)
}

func setup() {
	logger := log.New(os.Stdout, "[TEST SETUP] ", log.Ldate|log.Ltime)
	logger.Println("Starting test environment setup...")
	waitForKafka(logger)
	ensureTopicsExist(logger)
	initializeLocalStack(logger)
	logger.Println("Test environment setup completed successfully")
}

func TestKafkaTokenIssuanceAndRedeemFlow(t *testing.T) {
	t.Log("TESTING KAFKA TOKEN ISSUANCE AND REDEMPTION FLOW")
	issuerName := "TestIssuer-" + uuid.New().String()

	requestID := fmt.Sprintf("test-request-%d", time.Now().UnixNano())
	testMetadata := []byte(`{"user_id": "test-user", "timestamp": "2025-07-30T12:00:00Z"}`)
	testID := uuid.New().String()

	t.Logf("Test parameters: RequestID=%s, TestID=%s", requestID, testID)

	var tokens []*crypto.Token
	var blindedTokens []*crypto.BlindedToken
	var signingResultSet avroSchema.SigningResultV2Set
	t.Logf("Creating test issuer '%s'...", issuerName)

	now := time.Now()
	expires := now.Add(1 * time.Hour)

	issuerRequest := issuerV3CreateRequest{
		Name:      issuerName,
		Cohort:    1,
		MaxTokens: 500,
		ExpiresAt: &expires,
		ValidFrom: &now,
		Duration:  "PT1H30M",
		Overlap:   1,
		Buffer:    1,
	}

	t.Logf(
		"Issuer configuration: MaxTokens=%d, ValidFrom=%s, ExpiresAt=%s, Duration=%s, Overlap=%d, Buffer=%d",
		issuerRequest.MaxTokens,
		now.Format(time.RFC3339),
		expires.Format(time.RFC3339),
		issuerRequest.Duration,
		issuerRequest.Overlap,
		issuerRequest.Buffer,
	)
	createTestIssuer(t, issuerRequest)

	t.Run("issue_tokens", func(t *testing.T) {
		tokens, blindedTokens, signingResultSet = issueTokensViaKafka(
			t,
			testMetadata,
			testID,
			requestID,
			issuerRequest,
		)
		t.Logf("Successfully received signing results with %d tokens", len(tokens))
		require.NotEmpty(t, tokens, "Should have tokens after issuance")
		require.NotEmpty(t, blindedTokens, "Should have blinded tokens after issuance")
		require.NotEmpty(t, signingResultSet.Data, "Should have signing results after issuance")
	})

	t.Run("process_signing_results", func(t *testing.T) {
		for i, result := range signingResultSet.Data {
			t.Logf(
				"Processing signing result %d/%d",
				i+1,
				len(signingResultSet.Data),
			)

			require.Equal(
				t,
				avroSchema.SigningResultV2StatusOk,
				result.Status,
				"Signing should succeed for result %d",
				i,
			)

			require.NotEmpty(
				t,
				result.Signed_tokens,
				"Should have signed tokens in result %d",
				i,
			)

			require.NotEmpty(
				t,
				result.Issuer_public_key,
				"Should have public key in result %d",
				i,
			)

			require.NotEmpty(
				t,
				result.Proof,
				"Should have proof in result %d",
				i,
			)

			validFrom, _ := time.Parse(time.RFC3339, result.Valid_from.String)
			if validFrom.After(time.Now()) {
				t.Logf(
					"Skipping token with future key (valid from %s)",
					validFrom.Format(time.RFC3339),
				)
				continue
			}

			// Verify the rest of the test. This only needs to run once
			if i == 0 {
				t.Run("verify_and_redeem_token", func(t *testing.T) {
					var signedToken crypto.SignedToken
					err := signedToken.UnmarshalText([]byte(result.Signed_tokens[0]))
					require.NoError(t, err, "Should unmarshal signed token")

					var blindedToken crypto.BlindedToken
					err = blindedToken.UnmarshalText([]byte(result.Blinded_tokens[0]))
					require.NoError(t, err, "Should unmarshal blinded token")

					var issuerPublicKey crypto.PublicKey
					err = issuerPublicKey.UnmarshalText([]byte(result.Issuer_public_key))
					require.NoError(t, err, "Should unmarshal issuer public key")

					var batchDLEQProof crypto.BatchDLEQProof
					err = batchDLEQProof.UnmarshalText([]byte(result.Proof))
					require.NoError(t, err, "Should unmarshal batch DLEQ proof")

					verifyResult, err := batchDLEQProof.Verify(
						[]*crypto.BlindedToken{&blindedToken},
						[]*crypto.SignedToken{&signedToken},
						&issuerPublicKey,
					)
					require.NoError(t, err, "Should verify signed token")
					require.True(t, verifyResult, "DLEQ proof should be valid")

					var specificToken *crypto.Token
					for j, origBlinded := range blindedTokens {
						origBlindedText, _ := origBlinded.MarshalText()
						respBlindedText, _ := blindedToken.MarshalText()

						if bytes.Equal(origBlindedText, respBlindedText) {
							specificToken = tokens[j]
							break
						}
					}
					require.NotNil(t, specificToken, "Should find the original token")

					unblindedTokens, err := batchDLEQProof.VerifyAndUnblind(
						[]*crypto.Token{specificToken},
						[]*crypto.BlindedToken{&blindedToken},
						[]*crypto.SignedToken{&signedToken},
						&issuerPublicKey,
					)
					require.NoError(t, err, "Should verify and unblind token")
					require.Len(t, unblindedTokens, 1, "Should get exactly one unblinded token")

					signedUnblindedToken := unblindedTokens[0]
					tokenPreimage, _ := signedUnblindedToken.Preimage().MarshalText()
					signature, _ := signedUnblindedToken.DeriveVerificationKey().Sign("test")
					stringSignature, _ := signature.MarshalText()

					redeemRequest := avroSchema.RedeemRequest{
						Associated_data: testMetadata,
						Public_key:      result.Issuer_public_key,
						Token_preimage:  string(tokenPreimage),
						Binding:         "test",
						Signature:       string(stringSignature),
					}

					duplicateRequestID := requestID + "-duplicate"
					requestSet := &avroSchema.RedeemRequestSet{
						Request_id: duplicateRequestID,
						Data:       []avroSchema.RedeemRequest{redeemRequest},
					}

					var requestSetBuffer bytes.Buffer
					err = requestSet.Serialize(&requestSetBuffer)
					require.NoError(t, err, "Should serialize duplicate request")

					writer := kafka.NewWriter(kafka.WriterConfig{
						Brokers: []string{kafkaHost},
						Topic:   requestRedeemTopicName,
					})
					defer writer.Close()

					reader := kafka.NewReader(kafka.ReaderConfig{
						Brokers:     []string{kafkaHost},
						Topic:       responseRedeemTopicName,
						GroupID:     fmt.Sprintf("test-duplicate-%s", testID),
						StartOffset: kafka.LastOffset,
						MinBytes:    1,
						MaxBytes:    10e6,
						MaxWait:     100 * time.Millisecond,
					})
					defer reader.Close()

					t.Run("redeem_via_kafka", func(t *testing.T) {
						err = writer.WriteMessages(context.Background(),
							kafka.Message{
								Key:   []byte(requestID),
								Value: requestSetBuffer.Bytes(),
							},
						)
						require.NoError(t, err, "Should write redeem request to Kafka")

						ctx, cancel := context.WithTimeout(
							context.Background(),
							responseWaitDuration,
						)
						defer cancel()

						message, err := reader.ReadMessage(ctx)
						require.NoError(t, err, "Should read redemption response")

						resultSet, err := avroSchema.DeserializeRedeemResultSet(
							bytes.NewReader(message.Value),
						)
						require.NoError(t, err, "Should deserialize redemption response")

						require.Equal(t, requestID, resultSet.Request_id,
							"Response request ID should match")

						require.NotEmpty(t, resultSet.Data, "Should have redemption results")

						result := resultSet.Data[0]
						assert.NotEmpty(t, result.Issuer_name, "Should have issuer name")
						assert.Greater(t, result.Issuer_cohort, int32(-1), "Should have valid cohort")
						assert.Contains(t,
							[]avroSchema.RedeemResultStatus{
								avroSchema.RedeemResultStatusOk,
								avroSchema.RedeemResultStatusIdempotent_redemption,
							},
							result.Status,
							"Redemption should succeed")
					})

					t.Run("redeem_duplicate", func(t *testing.T) {
						err = writer.WriteMessages(context.Background(),
							kafka.Message{
								Key:   []byte(duplicateRequestID),
								Value: requestSetBuffer.Bytes(),
							},
						)
						require.NoError(t, err, "Should write duplicate request")

						ctx, cancel := context.WithTimeout(
							context.Background(),
							responseWaitDuration,
						)
						defer cancel()

						message, err := reader.ReadMessage(ctx)
						require.NoError(t, err, "Should read duplicate response")

						resultSet, err := avroSchema.DeserializeRedeemResultSet(
							bytes.NewReader(message.Value),
						)
						require.NoError(t, err, "Should deserialize duplicate response")

						require.Equal(t, duplicateRequestID, resultSet.Request_id,
							"Duplicate response ID should match")

						require.NotEmpty(t, resultSet.Data, "Should have duplicate results")

						result := resultSet.Data[0]
						assert.Equal(t,
							avroSchema.RedeemResultStatusDuplicate_redemption,
							result.Status,
							"Duplicate redemption should be detected")
					})
				})

				// Only need to run the detailed tests once
				break
			}
		}
	})
}

func TestIssuerV1(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}

	exp := time.Now().Add(time.Hour).UTC()

	issuerRequest := issuerV3CreateRequest{
		Name:      "TestIssuer-" + uuid.New().String(),
		Cohort:    1,
		MaxTokens: 1,
		ExpiresAt: &exp,
	}

	t.Run("create_issuer", func(t *testing.T) {
		body, err := json.Marshal(issuerRequest)
		require.NoError(t, err)

		req, err := http.NewRequest(
			http.MethodPost,
			"http://cbp:2416/v1/issuer",
			bytes.NewBuffer(body),
		)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("get_issuer", func(t *testing.T) {
		t.Log("TESTING HTTP ISSUER GET ENDPOINT")

		t.Logf("Retrieving issuer information for '%s'...", issuerRequest.Name)
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://cbp:2416/v1/issuer/%s", issuerRequest.Name),
			nil,
		)
		require.NoError(t, err, "failed to create GET issuer HTTP request")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err, "failed to make GET issuer HTTP request")
		defer resp.Body.Close()

		t.Logf("Issuer GET response status: %s", resp.Status)
		require.Equal(
			t,
			http.StatusOK,
			resp.StatusCode,
			"GET issuer request should succeed",
		)

		var issuerResp issuerResponse
		err = json.NewDecoder(resp.Body).Decode(&issuerResp)
		require.NoError(t, err, "failed to decode issuer response")

		t.Logf("Issuer details: ID=%s, Name=%s, Cohort=%d",
			issuerResp.ID, issuerResp.Name, issuerResp.Cohort)

		assert.NotEmpty(t, issuerResp.ID, "issuer ID should not be empty")
		assert.Equal(t, issuerRequest.Name, issuerResp.Name, "issuer name should match")
		assert.NotNil(t, issuerResp.PublicKey, "public key should not be nil")
		assert.Equal(t, int32(1), issuerResp.Cohort, "cohort should be 1")

		if issuerResp.ExpiresAt != "" {
			expiresAt, err := time.Parse(time.RFC3339, issuerResp.ExpiresAt)
			require.NoError(t, err, "failed to parse expires_at timestamp")

			if expiresAt.After(time.Now()) {
				t.Logf(
					"Expiration is correctly set in the future: %s",
					expiresAt.Format(time.RFC3339),
				)
			} else {
				t.Logf(
					"WARNING: Expiration is in the past: %s",
					expiresAt.Format(time.RFC3339),
				)
			}

			assert.True(
				t,
				expiresAt.After(time.Now()),
				"expiration should be in the future",
			)
		} else {
			t.Log("Note: Issuer doesn't have an expiration time set")
		}

		t.Log("Successfully validated issuer response")

		t.Log("Testing retrieval of non-existent issuer...")
		req, err = http.NewRequest(
			"GET",
			"http://cbp:2416/v1/issuer/NonExistentIssuer",
			nil,
		)
		require.NoError(
			t,
			err,
			"failed to create GET issuer HTTP request for non-existent issuer",
		)

		resp, err = client.Do(req)
		require.NoError(
			t,
			err,
			"failed to make GET issuer HTTP request for non-existent issuer",
		)
		defer resp.Body.Close()

		t.Logf("Non-existent issuer GET response status: %s", resp.Status)
		assert.Equal(
			t,
			http.StatusNotFound,
			resp.StatusCode,
			"non-existent issuer should return 404",
		)
		t.Log("Non-existent issuer correctly returned 404 Not Found")

		t.Log("HTTP ISSUER GET ENDPOINT TEST PASSED")
	})

	t.Run("issuer_not_found", func(t *testing.T) {
		req, err := http.NewRequest(
			http.MethodGet,
			"http://cbp:2416/v1/issuer/NonExistentIssuer",
			nil,
		)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestTokenIssuanceViaKafkaAndRedeemViaHTTPFlow(t *testing.T) {
	t.Log("TESTING TOKEN ISSUANCE VIA KAFKA AND REDEMPTION VIA HTTP")

	issuerName := "TestIssuer-" + uuid.New().String()
	requestID := fmt.Sprintf("test-request-%d", time.Now().UnixNano())
	testMetadata := []byte(`{"user_id": "test-user", "timestamp": "2025-07-30T12:00:00Z"}`)
	testID := uuid.New().String()

	t.Logf("Test parameters: IssuerName=%s, RequestID=%s, TestID=%s",
		issuerName, requestID, testID)

	var tokens []*crypto.Token
	var blindedTokens []*crypto.BlindedToken
	var signingResultSet avroSchema.SigningResultV2Set
	var allTokenInfos []tokenInfo

	t.Logf("Creating test issuer '%s'...", issuerName)

	now := time.Now()
	expires := now.Add(1 * time.Hour)

	issuerRequest := issuerV3CreateRequest{
		Name:      issuerName,
		Cohort:    1,
		MaxTokens: 500,
		ExpiresAt: &expires,
		ValidFrom: &now,
		Duration:  "PT1H30M",
		Overlap:   1,
		Buffer:    1,
	}

	t.Logf(
		"Issuer configuration: MaxTokens=%d, ValidFrom=%s, ExpiresAt=%s, Duration=%s, Overlap=%d, Buffer=%d",
		issuerRequest.MaxTokens,
		now.Format(time.RFC3339),
		expires.Format(time.RFC3339),
		issuerRequest.Duration,
		issuerRequest.Overlap,
		issuerRequest.Buffer,
	)
	createTestIssuer(t, issuerRequest)

	t.Run("issue_tokens_via_kafka", func(t *testing.T) {
		tokens, blindedTokens, signingResultSet = issueTokensViaKafka(
			t,
			testMetadata,
			testID,
			requestID,
			issuerRequest,
		)
		t.Logf(
			"Successfully received signing results with %d tokens and %d result entries",
			len(tokens),
			len(signingResultSet.Data),
		)
		require.NotEmpty(t, tokens, "Should have tokens after issuance")
		require.NotEmpty(t, blindedTokens, "Should have blinded tokens after issuance")
		require.NotEmpty(t, signingResultSet.Data, "Should have signing results after issuance")
	})

	t.Run("map_tokens_to_signing_keys", func(t *testing.T) {
		for i, originalBlindedToken := range blindedTokens {
			t.Logf("Processing token %d/%d...", i+1, len(blindedTokens))
			originalBlindedTokenBytes, _ := originalBlindedToken.MarshalText()
			originalBlindedTokenStr := string(originalBlindedTokenBytes)
			var foundMatch bool
			for j, result := range signingResultSet.Data {
				for k, resultBlindedTokenStr := range result.Blinded_tokens {
					if resultBlindedTokenStr == originalBlindedTokenStr {
						t.Logf(
							"Found matching blinded token in result %d at position %d",
							j,
							k,
						)
						foundMatch = true

						var batchDLEQProof crypto.BatchDLEQProof
						_ = batchDLEQProof.UnmarshalText([]byte(result.Proof))
						var issuerPublicKey crypto.PublicKey
						_ = issuerPublicKey.UnmarshalText([]byte(result.Issuer_public_key))
						var signedToken crypto.SignedToken
						_ = signedToken.UnmarshalText([]byte(result.Signed_tokens[k]))
						var blindedToken crypto.BlindedToken
						_ = blindedToken.UnmarshalText([]byte(resultBlindedTokenStr))

						resultUnblindedTokens, err := batchDLEQProof.VerifyAndUnblind(
							[]*crypto.Token{tokens[i]},
							[]*crypto.BlindedToken{&blindedToken},
							[]*crypto.SignedToken{&signedToken},
							&issuerPublicKey)

						require.NoError(
							t,
							err,
							"Should successfully verify and unblind",
						)
						require.Len(
							t,
							resultUnblindedTokens,
							1,
							"Should get exactly one unblinded token",
						)

						allTokenInfos = append(allTokenInfos, tokenInfo{
							UnblindedToken: resultUnblindedTokens[0],
							SignedKey:      result.Issuer_public_key,
						})
						break
					}
				}
				if foundMatch {
					break
				}
			}
			require.True(
				t,
				foundMatch,
				"token %d should have a matching result",
				i+1,
			)
		}
		require.Len(t, allTokenInfos, len(tokens),
			"Should have the same number of token infos as original tokens")
	})

	for i, token := range allTokenInfos {
		if i%2 == 0 {
			t.Run("redeem_v1_endpoint", func(t *testing.T) {
				testHTTPRedemption(t, issuerName, RedeemV1, token)
			})
		} else {
			t.Run("redeem_v3_endpoint", func(t *testing.T) {
				testHTTPRedemption(t, issuerName, RedeemV3, token)
			})
		}
	}
}

func testHTTPRedemption(
	t *testing.T,
	issuerName string,
	endpoint RedeemEndpoint,
	token tokenInfo,
) {
	client := &http.Client{Timeout: 30 * time.Second}
	payload := "test"
	signature, err := token.UnblindedToken.DeriveVerificationKey().Sign(payload)
	require.NoError(t, err, "Should be able to sign payload")

	redeemRequest := blindedTokenRedeemRequest{
		Payload:       payload,
		TokenPreimage: token.UnblindedToken.Preimage(),
		Signature:     signature,
	}

	jsonData, err := json.Marshal(redeemRequest)
	require.NoError(t, err, "Should marshal redemption request")

	url := fmt.Sprintf(
		"http://cbp:2416/%s/blindedToken/%s/redemption/",
		endpoint,
		issuerName,
	)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	require.NoError(t, err, "Should create HTTP request")
	req.Header.Set("Content-Type", "application/json")

	t.Run("successful_redemption", func(t *testing.T) {
		resp, err := client.Do(req)
		require.NoError(t, err, "Should make HTTP request")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Should read response body")

		assert.Equal(
			t,
			http.StatusOK,
			resp.StatusCode,
			`Should successfully redeem token.
			Instead received: %s
			Request: %s`,
			body,
			jsonData,
		)
	})

	t.Run("duplicate_redemption", func(t *testing.T) {
		resp, err := client.Do(req)
		require.NoError(t, err, "Should make HTTP request")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Should read response body")

		assert.Equal(
			t,
			http.StatusConflict,
			resp.StatusCode,
			`Duplicate redemption should be blocked with 409 Conflict.
			Instead received: %s
			Request: %s`,
			body,
			jsonData,
		)
	})
}

func waitForKafka(logger *log.Logger) {
	var conn *kafka.Conn
	var err error

	logger.Printf(
		"Attempting to connect to Kafka at %s (max %d attempts)...",
		kafkaHost,
		maxRetries,
	)

	for i := range maxRetries {
		conn, err = kafka.DialLeader(
			context.Background(),
			"tcp",
			kafkaHost,
			"dummy",
			0,
		)
		if err == nil {
			conn.Close()
			logger.Printf(
				"SUCCESS: Connected to Kafka after %d/%d attempts",
				i+1,
				maxRetries,
			)
			return
		}

		logger.Printf(
			"WARNING: Attempt %d/%d: Failed to connect to Kafka: %v",
			i+1,
			maxRetries,
			err,
		)
		logger.Printf("Retrying in %s...", retryInterval)
		time.Sleep(retryInterval)
	}

	logger.Fatalf(
		"FATAL: Failed to connect to Kafka after %d attempts: %v",
		maxRetries,
		err,
	)
}

func ensureTopicsExist(logger *log.Logger) {
	logger.Printf("Connecting to Kafka broker at %s to create topics...", kafkaHost)

	conn, err := kafka.Dial("tcp", kafkaHost)
	if err != nil {
		logger.Fatalf("FATAL: Failed to connect to Kafka: %v", err)
	}
	defer conn.Close()

	logger.Print("Finding Kafka controller...")
	controller, err := conn.Controller()
	if err != nil {
		logger.Fatalf("FATAL: Failed to get Kafka controller: %v", err)
	}

	controllerAddr := fmt.Sprintf("%s:%d", controller.Host, controller.Port)
	logger.Printf("Connecting to Kafka controller at %s...", controllerAddr)

	controllerConn, err := kafka.Dial("tcp", controllerAddr)
	if err != nil {
		logger.Fatalf("FATAL: Failed to connect to Kafka controller: %v", err)
	}
	defer controllerConn.Close()

	topicNames := []string{
		connectionTestTopicName,
		requestRedeemTopicName,
		responseRedeemTopicName,
		requestIssuanceTopicName,
		responseIssuanceTopicName,
	}

	logger.Print("Creating the following topics if they don't exist:")
	for _, topicName := range topicNames {
		logger.Printf("  - %s", topicName)
		err = controllerConn.CreateTopics(kafka.TopicConfig{
			Topic:             topicName,
			NumPartitions:     1,
			ReplicationFactor: 1,
		})

		if err != nil {
			logger.Printf(
				"WARNING: Topic creation error (may already exist): %v",
				err,
			)
		} else {
			logger.Printf("SUCCESS: Topic created successfully")
		}
	}
}

func initializeLocalStack(logger *log.Logger) {
	logger.Print("Creating AWS session for LocalStack...")

	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String("us-west-2"),
		Endpoint:         aws.String("http://localstack:4566"),
		Credentials:      credentials.NewStaticCredentials("test", "test", ""),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(true),
	})

	if err != nil {
		logger.Fatalf("FATAL: Failed to create AWS session: %v", err)
	}

	logger.Print("Creating DynamoDB client...")
	svc := dynamodb.New(sess)
	if svc == nil {
		logger.Fatal("FATAL: Failed to create DynamoDB client")
	}

	logger.Print("Setting up DynamoDB tables...")
	err = test.SetupDynamodbTables(svc)
	if err != nil {
		logger.Fatalf(
			"FATAL: Failed to initialize LocalStack DynamoDB tables: %v",
			err,
		)
	}

	logger.Print("SUCCESS: LocalStack DynamoDB setup completed successfully")
}

func createTestIssuer(t *testing.T, request issuerV3CreateRequest) {
	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "FATAL: Failed to marshal issuer creation request")

	t.Log("Sending POST request to create issuer...")
	req, err := http.NewRequest(
		"POST",
		"http://cbp:2416/v3/issuer/",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(t, err, "FATAL: Failed to create HTTP request")

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "FATAL: Failed to make HTTP request")
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err, "FATAL: Failed to read response body")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Logf(
			"SUCCESS: Issuer creation succeeded with status: %s",
			resp.Status,
		)
	} else {
		t.Logf("WARNING: Issuer creation returned status: %s", resp.Status)
	}
}

func issueTokensViaKafka(
	t *testing.T,
	testMetadata []byte,
	requestID string,
	testID string,
	issuer issuerV3CreateRequest,
) (
	[]*crypto.Token,
	[]*crypto.BlindedToken,
	avroSchema.SigningResultV2Set,
) {
	t.Logf("Issuing tokens via Kafka: RequestID=%s, TestID=%s", requestID, testID)

	var tokens []*crypto.Token
	var blindedTokens []*crypto.BlindedToken
	var marshaledBlindedTokens []string

	t.Log("Generating random tokens...")
	// Number of tokens must be divisible by the sum of Buffer and Overlap of the Issuer
	tokenCount := issuer.Buffer + issuer.Overlap
	for i := range tokenCount {
		t.Logf("Generating token %d/%d...", i+1, tokenCount)

		token, err := crypto.RandomToken()
		require.NoError(t, err, "Failed to generate random token %d", i+1)
		tokens = append(tokens, token)

		t.Logf("Blinding token %d/%d...", i+1, tokenCount)
		blindedToken := token.Blind()
		blindedTokens = append(blindedTokens, blindedToken)

		textToken, err := blindedToken.MarshalText()
		require.NoError(t, err, "Failed to marshal blinded token %d to text", i+1)
		marshaledBlindedTokens = append(marshaledBlindedTokens, string(textToken))
	}

	t.Log("Creating signing request...")
	signingRequest1 := avroSchema.SigningRequest{
		Associated_data: testMetadata,
		Blinded_tokens:  marshaledBlindedTokens,
		Issuer_type:     issuer.Name,
		Issuer_cohort:   issuer.Cohort,
	}

	signingRequestSet := &avroSchema.SigningRequestSet{
		Request_id: requestID,
		Data:       []avroSchema.SigningRequest{signingRequest1},
	}

	var signingRequestBuffer bytes.Buffer
	err := signingRequestSet.Serialize(&signingRequestBuffer)
	require.NoError(t, err, "Failed to serialize signing request to binary")

	t.Log("Setting up Kafka writer and reader...")
	signingWriter := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{kafkaHost},
		Topic:   requestIssuanceTopicName,
	})
	defer signingWriter.Close()

	signingReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     []string{kafkaHost},
		Topic:       responseIssuanceTopicName,
		GroupID:     fmt.Sprintf("test-signing-%s", testID),
		StartOffset: kafka.LastOffset,
		MinBytes:    1,
		MaxBytes:    10e6,
		MaxWait:     100 * time.Millisecond,
	})
	defer signingReader.Close()

	t.Log("Sending signing request to Kafka...")
	err = signingWriter.WriteMessages(context.Background(),
		kafka.Message{
			Key:   []byte(requestID),
			Value: signingRequestBuffer.Bytes(),
		},
	)
	require.NoError(t, err, "Failed to write signing request to Kafka")
	t.Log("Successfully sent token issuance request to Kafka")

	t.Logf("Waiting for signing response (timeout: %s)...", responseWaitDuration)
	ctx, cancel := context.WithTimeout(context.Background(), responseWaitDuration)
	defer cancel()

	message, err := signingReader.ReadMessage(ctx)
	require.NoError(t, err, "Failed to read signing response from Kafka")
	t.Log("Successfully received signing response from Kafka")

	t.Log("Deserializing signing response...")
	signingResultSet, err := avroSchema.DeserializeSigningResultV2Set(
		bytes.NewReader(message.Value),
	)
	require.NoError(t, err, "Failed to deserialize signing response")

	t.Logf("Verifying signing response: Expected RequestID=%s, Got RequestID=%s",
		requestID, signingResultSet.Request_id)

	require.Equal(t, requestID, signingResultSet.Request_id,
		"Request ID in signing response should match the request")

	t.Logf("Received %d signing results", len(signingResultSet.Data))
	require.Len(
		t,
		signingResultSet.Data,
		tokenCount,
		"Expected signing result count to match requested token count",
	)

	return tokens, blindedTokens, signingResultSet
}
