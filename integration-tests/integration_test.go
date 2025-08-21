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

// RedeemEndpoint identifies which redemption API to use
type RedeemEndpoint string

const (
	RedeemV1 RedeemEndpoint = "v1"
	RedeemV3 RedeemEndpoint = "v3"
	// Kafka settings
	kafkaHost            = "kafka:9092"
	maxRetries           = 10
	retryInterval        = 2 * time.Second
	responseWaitDuration = 30 * time.Second
)

var (
	connectionTestTopicName   = "test.connection." + uuid.New().String()
	requestRedeemTopicName    = os.Getenv("TEST_SHOULD_WRITE_REDEEM_REQUESTS_HERE")
	responseRedeemTopicName   = os.Getenv("TEST_SHOULD_READ_REDEEM_REQUESTS_HERE")
	requestIssuanceTopicName  = os.Getenv("TEST_SHOULD_WRITE_SIGNING_REQUESTS_HERE")
	responseIssuanceTopicName = os.Getenv("TEST_SHOULD_READ_SIGNING_REQUESTS_HERE")
	testIssuerSuffix          = uuid.New()
)

// tokenInfo represents an unblinded token and its signing key
type tokenInfo struct {
	UnblindedToken *crypto.UnblindedToken
	SignedKey      string
}

// API request/response types
type issuerResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Cohort    int16             `json:"cohort"`
}

type issuerV3CreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
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

// TestMain runs setup before all tests
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
	requestID := fmt.Sprintf("test-request-%d", time.Now().UnixNano())
	testMetadata := []byte(
		`{"user_id": "test-user", "timestamp": "2025-07-30T12:00:00Z"}`,
	)
	testID := uuid.New().String()

	t.Logf("Test parameters: RequestID=%s, TestID=%s", requestID, testID)
	t.Log("Step 1: Issuing tokens via Kafka...")
	tokens, blindedTokens, signingResultSet := issueTokensViaKafka(
		t,
		requestID,
		testMetadata,
		testID,
	)
	t.Logf("Successfully received signing results with %d tokens", len(tokens))

	// Unblind tokens and attempt to redeem each one
	t.Log("Step 2: Processing signing results and attempting redemption...")
	for i, result := range signingResultSet.Data {
		t.Logf("Processing signing result %d/%d", i+1, len(signingResultSet.Data))

		require.Equal(
			t,
			avroSchema.SigningResultV2StatusOk,
			result.Status,
			"Signing failed for result %d",
			i,
		)
		require.NotEmpty(
			t,
			result.Signed_tokens,
			"No signed tokens in result %d",
			i,
		)
		require.NotEmpty(
			t,
			result.Issuer_public_key,
			"No public key in result %d",
			i,
		)
		require.NotEmpty(t, result.Proof, "No proof in result %d", i)
		t.Logf(
			"Successfully received %d signed tokens for request %d",
			len(result.Signed_tokens),
			i+1,
		)

		validFrom, _ := time.Parse(time.RFC3339, result.Valid_from.String)
		// Skip tokens signed with future keys
		if validFrom.After(time.Now()) {
			t.Logf(
				"SKIPPING: Token signed with future key %s (valid from %s) - this is expected",
				result.Issuer_public_key,
				validFrom.Format(time.RFC3339),
			)
			continue
		}

		t.Log("Processing signed tokens...")
		var signedTokens []*crypto.SignedToken
		for _, signedTokenString := range result.Signed_tokens {
			var signedToken crypto.SignedToken
			err := signedToken.UnmarshalText([]byte(signedTokenString))
			require.NoError(t, err, "failed to unmarshal signed token")
			signedTokens = append(signedTokens, &signedToken)
		}

		t.Log("Processing blinded tokens...")
		var responseBlindedTokens []*crypto.BlindedToken
		for _, blindedTokenString := range result.Blinded_tokens {
			var blindedToken crypto.BlindedToken
			err := blindedToken.UnmarshalText([]byte(blindedTokenString))
			require.NoError(t, err, "failed to unmarshal blinded token")
			responseBlindedTokens = append(responseBlindedTokens, &blindedToken)
		}

		t.Log("Unmarshaling cryptographic parameters...")
		var (
			batchDLEQProof  crypto.BatchDLEQProof
			issuerPublicKey crypto.PublicKey
		)
		err := issuerPublicKey.UnmarshalText([]byte(result.Issuer_public_key))
		require.NoError(t, err, "failed to unmarshal issuer public key")
		err = batchDLEQProof.UnmarshalText([]byte(result.Proof))
		require.NoError(t, err, "failed to unmarshal batch DLEQ proof")

		// Verify signed tokens
		t.Log("Verifying signed tokens with DLEQ proof...")
		verifyResult, err := batchDLEQProof.Verify(
			responseBlindedTokens,
			signedTokens,
			&issuerPublicKey,
		)
		require.NoError(t, err, "failed to verify signed tokens")
		require.Equal(t, verifyResult, true, "DLEQ proof should be valid")
		t.Log("Successfully verified tokens with DLEQ proof")

		// REDEMPTION PHASE - Use the specific token that was signed with this key
		t.Log("Preparing for token redemption...")
		tokenIndex := 0
		if i > 0 {
			tokenIndex = 1 // For the second result, use the second token
			t.Log("Using second token for this redemption (i > 0)")
		} else {
			t.Log("Using first token for this redemption (i = 0)")
		}

		// Get the specific token that was signed with this issuer's key
		specificToken := tokens[tokenIndex]
		specificBlindedTokenText, err := blindedTokens[tokenIndex].MarshalText()
		require.NoError(t, err, "failed to marshal specific blinded tokens")

		// Find the signed token that corresponds to our blinded token
		t.Log("Finding the corresponding signed token...")
		var signedUnblindedToken *crypto.UnblindedToken
		var matchFound bool

		for j, respBlindedToken := range responseBlindedTokens {
			respBlindedTokenText, err := respBlindedToken.MarshalText()
			require.NoError(
				t,
				err,
				"failed to marshal response blinded tokens",
			)

			if bytes.Equal(respBlindedTokenText, specificBlindedTokenText) {
				t.Logf("Found matching token at index %d", j)
				matchFound = true

				// This is our token - unblind it with the corresponding signed token
				t.Log("Unblinding token...")
				unblindedTokens, err := batchDLEQProof.VerifyAndUnblind(
					[]*crypto.Token{specificToken},
					[]*crypto.BlindedToken{respBlindedToken},
					[]*crypto.SignedToken{signedTokens[j]},
					&issuerPublicKey,
				)
				require.NoError(
					t,
					err,
					"failed to verify and unblind specific token",
				)
				require.Len(
					t,
					unblindedTokens,
					1,
					"expected exactly one unblinded token",
				)

				signedUnblindedToken = unblindedTokens[0]
				break
			}
		}

		require.True(t, matchFound, "Should find a matching token")
		require.NotNil(
			t,
			signedUnblindedToken,
			"failed to find and unblind the specific token",
		)

		t.Log("Preparing redemption request...")
		tokenPreimage, err := signedUnblindedToken.Preimage().MarshalText()
		require.NoError(t, err, "failed to marshal preimage")

		signature, err := signedUnblindedToken.DeriveVerificationKey().Sign("test")
		require.NoError(t, err, "failed to create signature")

		stringSignature, err := signature.MarshalText()
		require.NoError(t, err, "failed to marshal signature")

		redeemRequest := avroSchema.RedeemRequest{
			Associated_data: testMetadata,
			Public_key:      result.Issuer_public_key,
			Token_preimage:  string(tokenPreimage),
			Binding:         "test",
			Signature:       string(stringSignature),
		}

		requestSet := &avroSchema.RedeemRequestSet{
			Request_id: requestID,
			Data:       []avroSchema.RedeemRequest{redeemRequest},
		}

		var requestSetBuffer bytes.Buffer
		err = requestSet.Serialize(&requestSetBuffer)
		require.NoError(t, err, "Failed to serialize redeem request to binary")

		t.Log("Setting up Kafka writer and reader for redemption...")
		writer := kafka.NewWriter(kafka.WriterConfig{
			Brokers: []string{kafkaHost},
			Topic:   requestRedeemTopicName,
		})
		defer writer.Close()

		reader := kafka.NewReader(kafka.ReaderConfig{
			Brokers:     []string{kafkaHost},
			Topic:       responseRedeemTopicName,
			GroupID:     fmt.Sprintf("test-signing-%s-%d", testID, i),
			StartOffset: kafka.LastOffset,
			MinBytes:    1,
			MaxBytes:    10e6,
			MaxWait:     100 * time.Millisecond,
		})
		defer reader.Close()

		t.Log("Sending redemption request to Kafka...")
		err = writer.WriteMessages(context.Background(),
			kafka.Message{
				Key:   []byte(requestID),
				Value: requestSetBuffer.Bytes(),
			},
		)
		require.NoError(t, err, "Failed to write redeem request to Kafka")
		t.Logf(
			"Successfully sent token redemption request to Kafka (RequestID: %s)",
			requestID,
		)

		t.Log("Waiting for redemption response from Kafka...")
		ctx, cancel := context.WithTimeout(
			context.Background(),
			responseWaitDuration,
		)
		defer cancel()

		var resultSet avroSchema.RedeemResultSet
		message, err := reader.ReadMessage(ctx)
		require.NoError(t, err, "Failed to read redemption response from Kafka")
		t.Log("Successfully received redemption message from Kafka")

		t.Log("Deserializing redemption response...")
		resultSet, err = avroSchema.DeserializeRedeemResultSet(
			bytes.NewReader(message.Value),
		)

		if err != nil {
			t.Logf("WARNING: Cannot deserialize redemption message: %v", err)
			t.Logf("Raw message content: %s", string(message.Value))
		}

		if resultSet.Request_id == requestID {
			t.Logf(
				"Found matching redemption response for request ID: %s",
				requestID,
			)
			t.Log("Validating response...")
			validateResponse(t, resultSet)
		} else {
			t.Logf(
				"WARNING: Received redemption message for different request ID: %s (expected: %s)",
				resultSet.Request_id,
				requestID,
			)
		}

		require.NotNil(t, resultSet, "Redemption response set should not be nil")
	}

	t.Log("KAFKA TOKEN ISSUANCE AND REDEMPTION FLOW TEST COMPLETED")
}

func TestIssuerV1(t *testing.T) {
	t.Cleanup(func() {
		_, _ = dbi.Exec("TRUNCATE TABLE issuers;")
	})

	client := &http.Client{Timeout: 30 * time.Second}

	exp := time.Now().Add(time.Hour).UTC()

	issReq := issuerV3CreateRequest{
		Name:      "test-issuer-V1",
		Cohort:    1,
		MaxTokens: 1,
		ExpiresAt: &exp,
	}

	t.Run("create_issuer", func(t *testing.T) {
		body, err := json.Marshal(issReq)
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
		issuerName := "TestIssuer-" + testIssuerSuffix.String()

		t.Logf("Retrieving issuer information for '%s'...", issuerName)
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://cbp:2416/v1/issuer/%s", issuerName),
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
		assert.Equal(t, issuerName, issuerResp.Name, "issuer name should match")
		assert.NotNil(t, issuerResp.PublicKey, "public key should not be nil")
		assert.Equal(t, int16(1), issuerResp.Cohort, "cohort should be 1")

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
	issuerName := "TestIssuer-" + testIssuerSuffix.String()
	requestID := fmt.Sprintf("test-request-%d", time.Now().UnixNano())
	testMetadata := []byte(
		`{"user_id": "test-user", "timestamp": "2025-07-30T12:00:00Z"}`,
	)
	testID := uuid.New().String()

	t.Logf("Test parameters: IssuerName=%s, RequestID=%s, TestID=%s",
		issuerName, requestID, testID)

	t.Log("Step 1: Issuing tokens via Kafka...")
	tokens, blindedTokens, signingResultSet := issueTokensViaKafka(
		t,
		requestID,
		testMetadata,
		testID,
	)
	t.Logf(
		"Successfully received signing results with %d tokens and %d result entries",
		len(tokens),
		len(signingResultSet.Data),
	)

	t.Log("Step 2: Mapping original blinded tokens to unblinded tokens and signing keys...")
	// Map each original blinded token to its unblinded token and signing key
	var allTokenInfos []tokenInfo
	for i, originalBlindedToken := range blindedTokens {
		t.Logf("Processing token %d/%d...", i+1, len(blindedTokens))

		originalBlindedTokenBytes, _ := originalBlindedToken.MarshalText()
		originalBlindedTokenStr := string(originalBlindedTokenBytes)

		var foundMatch bool
		for j, result := range signingResultSet.Data {
			t.Logf(
				"Checking against result %d/%d...",
				j+1,
				len(signingResultSet.Data),
			)

			for k, resultBlindedTokenStr := range result.Blinded_tokens {
				if resultBlindedTokenStr == originalBlindedTokenStr {
					t.Logf(
						"Found matching blinded token in result %d at position %d",
						j+1,
						k+1,
					)
					foundMatch = true

					// Correct batch-proof for this token
					t.Log("Unmarshaling cryptographic parameters...")
					var batchDLEQProof crypto.BatchDLEQProof
					_ = batchDLEQProof.UnmarshalText([]byte(result.Proof))

					var issuerPublicKey crypto.PublicKey
					_ = issuerPublicKey.UnmarshalText([]byte(result.Issuer_public_key))

					var signedToken crypto.SignedToken
					_ = signedToken.UnmarshalText([]byte(result.Signed_tokens[k]))

					var blindedToken crypto.BlindedToken
					_ = blindedToken.UnmarshalText([]byte(resultBlindedTokenStr))

					t.Log("Verifying and unblinding token...")
					resultUnblindedTokens, err := batchDLEQProof.VerifyAndUnblind(
						[]*crypto.Token{tokens[i]},
						[]*crypto.BlindedToken{&blindedToken},
						[]*crypto.SignedToken{&signedToken},
						&issuerPublicKey)

					if err != nil {
						t.Logf("WARNING: Error verifying and unblinding token: %v", err)
					} else {
						t.Log("Successfully verified and unblinded token")
					}

					require.Len(t, resultUnblindedTokens, 1, "Should get exactly one unblinded token")

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

		require.True(t, foundMatch, "token %d should have a matching result", i+1)
	}

	require.Len(t, allTokenInfos, len(tokens),
		"Should have the same number of token infos as original tokens")

	t.Logf("Successfully mapped %d tokens to their unblinded versions", len(allTokenInfos))

	t.Log("Step 3: Testing redemption via HTTP v1 endpoint...")
	doRedemptionHTTPTest(t, issuerName, RedeemV1, allTokenInfos)

	t.Log("Step 4: Testing redemption via HTTP v3 endpoint...")
	doRedemptionHTTPTest(t, issuerName, RedeemV3, allTokenInfos)

	t.Log("TOKEN ISSUANCE VIA KAFKA AND REDEMPTION VIA HTTP TEST COMPLETED")
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
			logger.Printf("WARNING: Topic creation error (may already exist): %v", err)
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

func createTestIssuer(logger *log.Logger, issuerName string, cohort int64) {
	issuerName := "TestIssuer-" + suffix
	logger.Printf("Creating test issuer '%s'...", issuerName)

	now := time.Now()
	expires := now.Add(1 * time.Hour)

	request := issuerV3CreateRequest{
		Name:      issuerName,
		Cohort:    1,
		MaxTokens: 500,
		ExpiresAt: &expires,
		ValidFrom: &now,
		Duration:  "PT1H30M",
		Overlap:   1,
		Buffer:    1,
	}

	logger.Printf(
		"Issuer configuration: MaxTokens=%d, ValidFrom=%s, ExpiresAt=%s, Duration=%s, Overlap=%d, Buffer=%d",
		request.MaxTokens,
		now.Format(time.RFC3339),
		expires.Format(time.RFC3339),
		request.Duration,
		request.Overlap,
		request.Buffer,
	)

	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "FATAL: Failed to marshal issuer creation request")

	logger.Print("Sending POST request to create issuer...")
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

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "FATAL: Failed to read response body")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Printf(
			"SUCCESS: Issuer creation succeeded with status: %s",
			resp.Status,
		)
	} else {
		logger.Printf("WARNING: Issuer creation returned status: %s", resp.Status)
	}
}

// Helper functions
func validateResponse(t *testing.T, response avroSchema.RedeemResultSet) {
	t.Logf("Validating redemption result set with %d results...", len(response.Data))

	for i, result := range response.Data {
		t.Logf("Validating result %d/%d...", i+1, len(response.Data))

		if result.Issuer_name == "" {
			t.Logf("WARNING: Result %d is missing issuer_name", i+1)
		} else {
			t.Logf("Result %d has issuer_name: %s", i+1, result.Issuer_name)
		}
		assert.NotEmpty(
			t,
			result.Issuer_name,
			"Result should have an issuer_name",
		)

		if result.Issuer_cohort < 0 {
			t.Logf(
				"WARNING: Result %d has invalid issuer_cohort: %d",
				i+1,
				result.Issuer_cohort,
			)
		} else {
			t.Logf(
				"Result %d has issuer_cohort: %d",
				i+1,
				result.Issuer_cohort,
			)
		}
		assert.Greater(
			t,
			result.Issuer_cohort,
			int32(-1),
			"Issuer cohort should be a valid value",
		)

		validStatuses := []avroSchema.RedeemResultStatus{
			avroSchema.RedeemResultStatusOk,
			avroSchema.RedeemResultStatusDuplicate_redemption,
			avroSchema.RedeemResultStatusUnverified,
			avroSchema.RedeemResultStatusError,
			avroSchema.RedeemResultStatusIdempotent_redemption,
		}

		t.Logf("Result %d status: %s", i+1, result.Status)

		assert.Contains(
			t,
			validStatuses,
			result.Status,
			"Status should be a valid redemption status",
		)

		if result.Associated_data == nil {
			t.Logf("WARNING: Result %d is missing associated data", i+1)
		} else {
			t.Logf("Result %d has associated data present", i+1)
		}
		assert.NotNil(
			t,
			result.Associated_data,
			"Associated data should not be nil",
		)

		if result.Status == avroSchema.RedeemResultStatusOk {
			t.Logf("SUCCESS: Result %d redemption succeeded (status: OK)", i+1)
		} else if result.Status == avroSchema.RedeemResultStatusDuplicate_redemption {
			t.Logf("NOTE: Result %d is a duplicate redemption - this is expected when tokens are reused", i+1)
		} else if result.Status == avroSchema.RedeemResultStatusIdempotent_redemption {
			t.Logf("NOTE: Result %d is an idempotent redemption - this is expected for repeated requests", i+1)
		} else {
			t.Logf("WARNING: Result %d redemption status: %s (non-fatal, may be expected)", i+1, result.Status)
		}
	}
}

func issueTokensViaKafka(
	t *testing.T,
	requestID string,
	testMetadata []byte,
	testID string,
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
	for i := range 2 {
		t.Logf("Generating token %d/2...", i+1)

		token, err := crypto.RandomToken()
		require.NoError(t, err, "Failed to generate random token %d", i+1)
		tokens = append(tokens, token)

		t.Logf("Blinding token %d/2...", i+1)
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
		Issuer_type:     "TestIssuer",
		Issuer_cohort:   1,
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
	require.Len(t, signingResultSet.Data, 2, "Expected 2 signing results")

	return tokens, blindedTokens, signingResultSet
}

func doRedemptionHTTPTest(
	t *testing.T,
	issuerName string,
	which RedeemEndpoint,
	tokenInfos []tokenInfo,
) {
	t.Logf("TESTING HTTP REDEMPTION VIA %s ENDPOINT", which)
	t.Logf("Issuer: %s, Token count: %d", issuerName, len(tokenInfos))

	client := &http.Client{Timeout: 30 * time.Second}

	// Get the current active key for logs
	t.Log("Retrieving current active key from issuer...")
	issuerReq, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://cbp:2416/v3/issuer/%s", issuerName),
		nil,
	)
	if err != nil {
		t.Logf("WARNING: Failed to create issuer request: %v", err)
	}

	issuerResp, err := client.Do(issuerReq)
	if err != nil {
		t.Logf("WARNING: Failed to retrieve issuer info: %v", err)
	} else {
		defer issuerResp.Body.Close()

		var issuerInfo struct {
			PublicKey string `json:"public_key"`
		}

		err = json.NewDecoder(issuerResp.Body).Decode(&issuerInfo)
		if err != nil {
			t.Logf("WARNING: Failed to decode issuer response: %v", err)
		} else {
			t.Logf("Current active key: %s", issuerInfo.PublicKey)
		}
	}

	t.Log("Attempting to redeem each token...")
	succeeded := 0
	for i, ti := range tokenInfos {
		t.Logf("Processing token %d/%d (signed with key: %s)...",
			i+1, len(tokenInfos), ti.SignedKey)

		payload := "test"
		signature, err := ti.UnblindedToken.DeriveVerificationKey().Sign(payload)
		if err != nil {
			t.Logf(
				"WARNING: Failed to sign payload for token %d: %v",
				i+1,
				err,
			)
			continue
		}

		redeemRequest := blindedTokenRedeemRequest{
			Payload:       payload,
			TokenPreimage: ti.UnblindedToken.Preimage(),
			Signature:     signature,
		}

		jsonData, err := json.Marshal(redeemRequest)
		if err != nil {
			t.Logf(
				"WARNING: Failed to marshal redemption request for token %d: %v",
				i+1,
				err,
			)
			continue
		}

		url := fmt.Sprintf(
			"http://cbp:2416/%s/blindedToken/%s/redemption/",
			which,
			issuerName,
		)
		t.Logf("Sending redemption request to: %s", url)

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			t.Logf(
				"WARNING: Failed to create HTTP request for token %d: %v",
				i+1,
				err,
			)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Logf(
				"WARNING: Failed to make HTTP request for token %d: %v",
				i+1,
				err,
			)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Logf(
				"SUCCESS: Token #%d successfully redeemed (status: %s)",
				i+1,
				resp.Status,
			)
			succeeded++

			t.Logf("Testing duplicate detection for token #%d...", i+1)

			req2, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				t.Logf(
					"WARNING: Failed to create duplicate HTTP request: %v",
					err,
				)
				continue
			}

			req2.Header.Set("Content-Type", "application/json")
			resp2, err := client.Do(req2)
			if err != nil {
				t.Logf(
					"WARNING: Failed to make duplicate HTTP request: %v",
					err,
				)
				continue
			}

			defer resp2.Body.Close()

			if resp2.StatusCode == http.StatusConflict {
				t.Logf(
					"SUCCESS: Duplicate correctly detected (status: %s)",
					resp2.Status,
				)
			} else {
				t.Logf(
					"ERROR: Duplicate NOT correctly detected (expected 409 Conflict, got %d: %s)",
					resp2.StatusCode,
					resp2.Status,
				)
			}

			require.Equal(
				t,
				http.StatusConflict,
				resp2.StatusCode,
				"Duplicate redemption should be blocked with 409 Conflict",
			)
		} else {
			// Some failures are expected, especially for tokens with future keys
			bodyExcerpt := string(body)
			if len(bodyExcerpt) > 100 {
				bodyExcerpt = bodyExcerpt[:100] + "..."
			}
			t.Logf("NOTE: Token #%d failed to redeem (status: %s): %s",
				i+1, resp.Status, bodyExcerpt)
			t.Logf("This may be expected if the token's key is not currently active")
		}
	}

	t.Logf("Successfully redeemed %d/%d tokens", succeeded, len(tokenInfos))
	require.GreaterOrEqualf(
		t,
		succeeded,
		1,
		"At least one token must be redeemable! Zero redemptions indicates a critical problem.")

	t.Logf("HTTP REDEMPTION VIA %s ENDPOINT TEST COMPLETED", which)
}
