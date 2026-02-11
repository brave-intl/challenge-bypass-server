package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/brave-intl/challenge-bypass-server/utils/test"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/suite"
)

type ManageKeysTestSuite struct {
	suite.Suite
	handler        http.Handler
	accessToken    string
	srv            *Server
	signingKeys    *testSigningKeys
	cleanupSigners func()
}

func TestManageKeysTestSuite(t *testing.T) {
	suite.Run(t, new(ManageKeysTestSuite))
}

func (suite *ManageKeysTestSuite) SetupSuite() {
	err := os.Setenv("ENV", "localtest")
	suite.Require().NoError(err)

	uuidV4, err := uuid.NewRandom()
	suite.Require().NoError(err)
	suite.accessToken = uuidV4.String()
	TokenList = []string{suite.accessToken}

	// Setup test signing keys for management API
	suite.signingKeys, suite.cleanupSigners = setupTestSigningKeys()

	suite.srv = &Server{}

	err = suite.srv.InitDBConfig()
	suite.Require().NoError(err, "Failed to setup db conn")

	suite.srv.InitDB(slog.New(slog.DiscardHandler))
	suite.srv.InitDynamo()

	_, suite.handler = suite.srv.setupRouter(
		SetupLogger(
			context.Background(),
			Version,
			BuildTime,
			Commit,
		))

	err = test.SetupDynamodbTables(suite.srv.dynamo)
	suite.Require().NoError(err)
}

func (suite *ManageKeysTestSuite) TearDownSuite() {
	if suite.cleanupSigners != nil {
		suite.cleanupSigners()
	}
}

func (suite *ManageKeysTestSuite) SetupTest() {
	tables := []string{"v3_issuer_keys", "v3_issuers", "redemptions"}
	for _, table := range tables {
		_, err := suite.srv.db.Exec(fmt.Sprintf("delete from %s", table))
		suite.Require().NoError(err, "Failed to get clean table")
	}
}

func (suite *ManageKeysTestSuite) request(method, url string, body []byte) (*http.Response, error) {
	req, err := suite.signingKeys.signedRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+suite.accessToken)

	return http.DefaultClient.Do(req)
}

// createTestIssuer creates a test issuer and returns it
func (suite *ManageKeysTestSuite) createTestIssuer() *model.Issuer {
	issuer := model.Issuer{
		Version:      3,
		IssuerType:   test.RandomString(),
		IssuerCohort: 1,
		MaxTokens:    10,
		ExpiresAt:    pq.NullTime{Time: time.Now().Add(24 * time.Hour), Valid: true},
		Buffer:       2,
		Overlap:      0,
		Duration:     ptr.FromString("P1D"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}
	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, issuer.IssuerType)
	suite.Require().NoError(err)

	return createdIssuer
}

// Test listing keys for an issuer
func (suite *ManageKeysTestSuite) TestManageListKeys_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys", server.URL, issuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result KeyListResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	// The issuer should have keys created by createV3Issuer (buffer=2)
	suite.Assert().Equal(2, result.Total)
	suite.Assert().Len(result.Keys, 2)
}

// Test listing keys with include_expired parameter
func (suite *ManageKeysTestSuite) TestManageListKeys_IncludeExpired() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Request with include_expired=true
	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys?include_expired=true", server.URL, issuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result KeyListResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().GreaterOrEqual(result.Total, 2)
}

// Test listing keys with invalid issuer UUID
func (suite *ManageKeysTestSuite) TestManageListKeys_InvalidUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("GET", server.URL+"/api/v1/manage/issuers/not-a-uuid/keys", nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test getting a specific key
func (suite *ManageKeysTestSuite) TestManageGetKey_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get the list of keys first
	keys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(keys)

	keyID := keys[0].ID.String()

	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/%s", server.URL, issuer.ID.String(), keyID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result IssuerKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Equal(keyID, result.ID)
	suite.Assert().NotEmpty(result.PublicKey)
}

// Test getting a non-existent key
func (suite *ManageKeysTestSuite) TestManageGetKey_NotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()
	randomKeyID := uuid.New().String()

	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/%s", server.URL, issuer.ID.String(), randomKeyID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test getting a key with invalid issuer UUID
func (suite *ManageKeysTestSuite) TestManageGetKey_InvalidIssuerUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("GET", server.URL+"/api/v1/manage/issuers/not-a-uuid/keys/"+uuid.New().String(), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test getting a key with invalid key UUID
func (suite *ManageKeysTestSuite) TestManageGetKey_InvalidKeyUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/not-a-uuid", server.URL, issuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test creating a new key
func (suite *ManageKeysTestSuite) TestManageCreateKey_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get initial key count
	initialKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	initialCount := len(initialKeys)

	// Create a new key
	startAt := time.Now().Add(48 * time.Hour)
	endAt := time.Now().Add(72 * time.Hour)
	req := CreateKeyRequest{
		StartAt: &startAt,
		EndAt:   &endAt,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys", server.URL, issuer.ID.String()), payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result IssuerKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().NotEmpty(result.ID)
	suite.Assert().NotEmpty(result.PublicKey)
	suite.Assert().NotNil(result.StartAt)
	suite.Assert().NotNil(result.EndAt)

	// Verify key count increased
	newKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Assert().Equal(initialCount+1, len(newKeys))
}

// Test creating a key with empty body (defaults)
func (suite *ManageKeysTestSuite) TestManageCreateKey_EmptyBody() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys", server.URL, issuer.ID.String()), []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result IssuerKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().NotEmpty(result.ID)
	suite.Assert().NotEmpty(result.PublicKey)
}

// Test creating a key for non-existent issuer
func (suite *ManageKeysTestSuite) TestManageCreateKey_IssuerNotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	randomID := uuid.New().String()
	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys", server.URL, randomID), []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test creating a key with invalid issuer UUID
func (suite *ManageKeysTestSuite) TestManageCreateKey_InvalidIssuerUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers/not-a-uuid/keys", []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test deleting a key with force flag
func (suite *ManageKeysTestSuite) TestManageDeleteKey_Force_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get a key to delete
	keys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(keys)

	keyID := keys[0].ID.String()

	// Force delete the key
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/%s?force=true", server.URL, issuer.ID.String(), keyID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNoContent, resp.StatusCode)

	// Verify the key was deleted
	_, err = suite.srv.fetchKeyByID(issuer.ID.String(), keyID)
	suite.Assert().Equal(errKeyNotFound, err)
}

// Test deleting an active key without force flag
func (suite *ManageKeysTestSuite) TestManageDeleteKey_ActiveKey_Conflict() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get an active key
	keys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), false)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(keys)

	keyID := keys[0].ID.String()

	// Try to delete without force flag - should fail
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/%s", server.URL, issuer.ID.String(), keyID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode)
}

// Test deleting a non-existent key
func (suite *ManageKeysTestSuite) TestManageDeleteKey_NotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()
	randomKeyID := uuid.New().String()

	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/%s", server.URL, issuer.ID.String(), randomKeyID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test deleting a key with invalid issuer UUID
func (suite *ManageKeysTestSuite) TestManageDeleteKey_InvalidIssuerUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("DELETE", server.URL+"/api/v1/manage/issuers/not-a-uuid/keys/"+uuid.New().String(), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test deleting a key with invalid key UUID
func (suite *ManageKeysTestSuite) TestManageDeleteKey_InvalidKeyUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/not-a-uuid", server.URL, issuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test rotating keys
func (suite *ManageKeysTestSuite) TestManageRotateKeys_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get initial key count
	initialKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	initialCount := len(initialKeys)

	// Rotate keys with count=2
	req := RotateKeysRequest{
		Count: 2,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/rotate", server.URL, issuer.ID.String()), payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result RotateKeysResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Len(result.CreatedKeys, 2)
	suite.Assert().Equal("Keys rotated successfully", result.Message)

	// Verify key count increased
	newKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Assert().Equal(initialCount+2, len(newKeys))
}

// Test rotating keys with default count (1)
func (suite *ManageKeysTestSuite) TestManageRotateKeys_DefaultCount() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get initial key count
	initialKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	initialCount := len(initialKeys)

	// Rotate keys with empty body (default count=1)
	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/rotate", server.URL, issuer.ID.String()), []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result RotateKeysResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Len(result.CreatedKeys, 1)

	// Verify key count increased by 1
	newKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Assert().Equal(initialCount+1, len(newKeys))
}

// Test rotating keys for non-existent issuer
func (suite *ManageKeysTestSuite) TestManageRotateKeys_IssuerNotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	randomID := uuid.New().String()
	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/rotate", server.URL, randomID), []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test rotating keys with invalid issuer UUID
func (suite *ManageKeysTestSuite) TestManageRotateKeys_InvalidUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers/not-a-uuid/keys/rotate", []byte("{}"))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test rotating keys with overlap - ensures old keys get updated expiration
func (suite *ManageKeysTestSuite) TestManageRotateKeys_WithOverlap() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Get the initial key (created by createTestIssuer)
	initialKeys, err := suite.srv.fetchAllIssuerKeys(issuer.ID.String(), true)
	suite.Require().NoError(err)
	suite.Require().Greater(len(initialKeys), 0, "Should have at least one initial key")

	initialKey := initialKeys[0]
	originalEndAt := initialKey.EndAt

	// Rotate keys with a 7-day overlap
	req := RotateKeysRequest{
		Count:   1,
		Overlap: "P7D", // 7 days
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/rotate", server.URL, issuer.ID.String()), payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result RotateKeysResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	// Should have one created key
	suite.Assert().Len(result.CreatedKeys, 1)
	suite.Assert().NotEmpty(result.CreatedKeys[0].ID)

	// Should have one updated key (the original key with new end_at)
	suite.Assert().Len(result.UpdatedKeys, 1)
	suite.Assert().Equal(initialKey.ID.String(), result.UpdatedKeys[0].ID)

	// Parse the updated key's end_at
	updatedEndAtStr := result.UpdatedKeys[0].EndAt
	suite.Require().NotNil(updatedEndAtStr)
	updatedEndAt, err := time.Parse(time.RFC3339, *updatedEndAtStr)
	suite.Require().NoError(err)

	// Parse the new key's start_at
	newKeyStartStr := result.CreatedKeys[0].StartAt
	suite.Require().NotNil(newKeyStartStr)
	newKeyStart, err := time.Parse(time.RFC3339, *newKeyStartStr)
	suite.Require().NoError(err)

	// The updated key should expire after the new key starts
	suite.Assert().True(updatedEndAt.After(newKeyStart),
		"Updated key end_at (%v) should be after new key start_at (%v)",
		updatedEndAt, newKeyStart)

	// The updated key should have a different (earlier) expiration than before
	if originalEndAt != nil && !originalEndAt.IsZero() {
		suite.Assert().True(updatedEndAt.Before(*originalEndAt),
			"Updated key end_at (%v) should be earlier than original end_at (%v)",
			updatedEndAt, originalEndAt)
	}

	suite.Assert().Equal("Keys rotated successfully", result.Message)
}

// Test rotating keys with default overlap (should be 1 month)
func (suite *ManageKeysTestSuite) TestManageRotateKeys_DefaultOverlap() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	issuer := suite.createTestIssuer()

	// Rotate without specifying overlap
	req := RotateKeysRequest{
		Count: 1,
		// Overlap not specified, should default to P1M (1 month)
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", fmt.Sprintf("%s/api/v1/manage/issuers/%s/keys/rotate", server.URL, issuer.ID.String()), payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	var result RotateKeysResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	// Should have created and updated keys
	suite.Assert().Len(result.CreatedKeys, 1)
	suite.Assert().Len(result.UpdatedKeys, 1)
	suite.Assert().Equal("Keys rotated successfully", result.Message)
}

// Test makeKeyResponse helper function
func (suite *ManageKeysTestSuite) TestMakeKeyResponse() {
	keyID := uuid.New()
	issuerID := uuid.New()
	publicKey := "test-public-key"
	startAt := time.Now()
	endAt := time.Now().Add(24 * time.Hour)
	createdAt := time.Now().Add(-1 * time.Hour)

	key := &model.IssuerKeys{
		ID:        &keyID,
		IssuerID:  &issuerID,
		PublicKey: &publicKey,
		Cohort:    5,
		StartAt:   &startAt,
		EndAt:     &endAt,
		CreatedAt: &createdAt,
	}

	resp := makeKeyResponse(key)

	suite.Assert().Equal(keyID.String(), resp.ID)
	suite.Assert().Equal(publicKey, resp.PublicKey)
	suite.Assert().Equal(int16(5), resp.Cohort)
	suite.Assert().NotNil(resp.StartAt)
	suite.Assert().NotNil(resp.EndAt)
	suite.Assert().NotNil(resp.CreatedAt)
}

// Test makeKeyResponse with nil values
func (suite *ManageKeysTestSuite) TestMakeKeyResponse_NilValues() {
	key := &model.IssuerKeys{
		Cohort: 1,
		// ID, PublicKey, StartAt, EndAt, CreatedAt are nil
	}

	resp := makeKeyResponse(key)

	suite.Assert().Empty(resp.ID)
	suite.Assert().Empty(resp.PublicKey)
	suite.Assert().Equal(int16(1), resp.Cohort)
	suite.Assert().Nil(resp.StartAt)
	suite.Assert().Nil(resp.EndAt)
	suite.Assert().Nil(resp.CreatedAt)
}

// Test isKeyActive helper function
func (suite *ManageKeysTestSuite) TestIsKeyActive() {
	// Key with no end_at (never expires) - should be active
	keyNoExpiry := &model.IssuerKeys{
		EndAt: nil,
	}
	suite.Assert().True(isKeyActive(keyNoExpiry))

	// Key with zero end_at - should be active
	zeroTime := time.Time{}
	keyZeroExpiry := &model.IssuerKeys{
		EndAt: &zeroTime,
	}
	suite.Assert().True(isKeyActive(keyZeroExpiry))

	// Key with future end_at - should be active
	futureTime := time.Now().Add(24 * time.Hour)
	keyFuture := &model.IssuerKeys{
		EndAt: &futureTime,
	}
	suite.Assert().True(isKeyActive(keyFuture))

	// Key with past end_at - should not be active
	pastTime := time.Now().Add(-24 * time.Hour)
	keyPast := &model.IssuerKeys{
		EndAt: &pastTime,
	}
	suite.Assert().False(isKeyActive(keyPast))
}

// Test countActiveKeys helper function
func (suite *ManageKeysTestSuite) TestCountActiveKeys() {
	futureTime := time.Now().Add(24 * time.Hour)
	pastTime := time.Now().Add(-24 * time.Hour)

	keys := []model.IssuerKeys{
		{EndAt: nil},          // Active (no expiry)
		{EndAt: &futureTime},  // Active (future expiry)
		{EndAt: &pastTime},    // Inactive (past expiry)
		{EndAt: &time.Time{}}, // Active (zero time)
	}

	count := countActiveKeys(keys)
	suite.Assert().Equal(3, count)
}

// Test countActiveKeys with empty slice
func (suite *ManageKeysTestSuite) TestCountActiveKeys_Empty() {
	keys := []model.IssuerKeys{}
	count := countActiveKeys(keys)
	suite.Assert().Equal(0, count)
}

// Test countActiveKeys with all active keys
func (suite *ManageKeysTestSuite) TestCountActiveKeys_AllActive() {
	futureTime := time.Now().Add(24 * time.Hour)
	keys := []model.IssuerKeys{
		{EndAt: nil},
		{EndAt: &futureTime},
		{EndAt: nil},
	}

	count := countActiveKeys(keys)
	suite.Assert().Equal(3, count)
}

// Test countActiveKeys with all inactive keys
func (suite *ManageKeysTestSuite) TestCountActiveKeys_AllInactive() {
	pastTime := time.Now().Add(-24 * time.Hour)
	keys := []model.IssuerKeys{
		{EndAt: &pastTime},
		{EndAt: &pastTime},
	}

	count := countActiveKeys(keys)
	suite.Assert().Equal(0, count)
}

// Test invalidateIssuerCaches helper function
func (suite *ManageKeysTestSuite) TestInvalidateIssuerCaches_NilCaches() {
	// Server with nil caches should not panic
	srv := &Server{
		caches: nil,
	}
	suite.Assert().NotPanics(func() {
		srv.invalidateIssuerCaches()
	})
}
