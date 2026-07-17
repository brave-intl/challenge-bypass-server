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

type ManageIssuersTestSuite struct {
	suite.Suite
	handler        http.Handler
	accessToken    string
	srv            *Server
	signingKeys    *testSigningKeys
	cleanupSigners func()
}

func TestManageIssuersTestSuite(t *testing.T) {
	suite.Run(t, new(ManageIssuersTestSuite))
}

func (suite *ManageIssuersTestSuite) SetupSuite() {
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

func (suite *ManageIssuersTestSuite) TearDownSuite() {
	if suite.cleanupSigners != nil {
		suite.cleanupSigners()
	}
}

func (suite *ManageIssuersTestSuite) SetupTest() {
	tables := []string{"v3_issuer_keys", "v3_issuers", "redemptions"}
	for _, table := range tables {
		_, err := suite.srv.db.Exec(fmt.Sprintf("delete from %s", table))
		suite.Require().NoError(err, "Failed to get clean table")
	}
}

func (suite *ManageIssuersTestSuite) request(method, url string, body []byte) (*http.Response, error) {
	req, err := suite.signingKeys.signedRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+suite.accessToken)

	return http.DefaultClient.Do(req)
}

// Test listing issuers when none exist
func (suite *ManageIssuersTestSuite) TestManageListIssuers_Empty() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("GET", server.URL+"/api/v1/manage/issuers", nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result IssuerListResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Equal(0, result.Total)
	suite.Assert().Empty(result.Issuers)
}

// Test listing issuers with existing issuers
func (suite *ManageIssuersTestSuite) TestManageListIssuers_WithIssuers() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Create a test issuer
	issuer := model.Issuer{
		Version:      3,
		IssuerType:   test.RandomString(),
		IssuerCohort: 1,
		MaxTokens:    10,
		ExpiresAt:    pq.NullTime{Time: time.Now().Add(24 * time.Hour), Valid: true},
		Buffer:       2,
		Overlap:      1,
		Duration:     ptr.FromString("P1D"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}
	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	resp, err := suite.request("GET", server.URL+"/api/v1/manage/issuers", nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result IssuerListResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Equal(1, result.Total)
	suite.Assert().Len(result.Issuers, 1)
	suite.Assert().Equal(issuer.IssuerType, result.Issuers[0].Name)
	suite.Assert().Equal(issuer.IssuerCohort, result.Issuers[0].Cohort)
}

// Test getting a specific issuer by ID
func (suite *ManageIssuersTestSuite) TestManageGetIssuer_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Create a test issuer
	issuer := model.Issuer{
		Version:      3,
		IssuerType:   test.RandomString(),
		IssuerCohort: 2,
		MaxTokens:    20,
		ExpiresAt:    pq.NullTime{Time: time.Now().Add(48 * time.Hour), Valid: true},
		Buffer:       3,
		Overlap:      1,
		Duration:     ptr.FromString("P1D"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}
	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	// Fetch the issuer to get the ID
	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, issuer.IssuerType)
	suite.Require().NoError(err)

	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s", server.URL, createdIssuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	var result IssuerDetailResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.Require().NoError(err)

	suite.Assert().Equal(createdIssuer.ID.String(), result.ID)
	suite.Assert().Equal(issuer.IssuerType, result.Name)
	suite.Assert().Equal(issuer.IssuerCohort, result.Cohort)
	suite.Assert().Equal(issuer.MaxTokens, result.MaxTokens)
}

// Test getting a non-existent issuer
func (suite *ManageIssuersTestSuite) TestManageGetIssuer_NotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	randomID := uuid.New().String()
	resp, err := suite.request("GET", fmt.Sprintf("%s/api/v1/manage/issuers/%s", server.URL, randomID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test getting an issuer with invalid UUID format
func (suite *ManageIssuersTestSuite) TestManageGetIssuer_InvalidUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("GET", server.URL+"/api/v1/manage/issuers/not-a-uuid", nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test creating a v3 issuer
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V3_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	req := CreateIssuerRequest{
		Name:      test.RandomString(),
		Cohort:    1,
		MaxTokens: 50,
		Version:   3,
		ExpiresAt: &expiresAt,
		Duration:  "P1D",
		Buffer:    5,
		Overlap:   2,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	// Verify the issuer was created
	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, req.Name)
	suite.Require().NoError(err)
	suite.Assert().Equal(req.Name, createdIssuer.IssuerType)
	suite.Assert().Equal(req.Cohort, createdIssuer.IssuerCohort)
	suite.Assert().Equal(req.MaxTokens, createdIssuer.MaxTokens)
	suite.Assert().Equal(req.Version, createdIssuer.Version)
	suite.Assert().Equal(req.Buffer, createdIssuer.Buffer)
	suite.Assert().Equal(req.Overlap, createdIssuer.Overlap)
}

// Test creating a v1 issuer (should not require v3-specific fields)
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V1_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	req := CreateIssuerRequest{
		Name:      test.RandomString(),
		Cohort:    1,
		MaxTokens: 50,
		Version:   1,
		ExpiresAt: &expiresAt,
		// No Buffer, Duration, or Overlap for v1
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	// Verify the issuer was created with correct version
	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, req.Name)
	suite.Require().NoError(err)
	suite.Assert().Equal(req.Name, createdIssuer.IssuerType)
	suite.Assert().Equal(req.Cohort, createdIssuer.IssuerCohort)
	suite.Assert().Equal(req.MaxTokens, createdIssuer.MaxTokens)
	suite.Assert().Equal(1, createdIssuer.Version)
	// V3 fields should be zero/nil for v1
	suite.Assert().Equal(0, createdIssuer.Buffer)
	suite.Assert().Nil(createdIssuer.Duration)
}

// Test creating a v2 issuer (should not require v3-specific fields)
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V2_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	req := CreateIssuerRequest{
		Name:      test.RandomString(),
		Cohort:    2,
		MaxTokens: 40,
		Version:   2,
		ExpiresAt: &expiresAt,
		// No Buffer, Duration, or Overlap for v2
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	// Verify the issuer was created with correct version
	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, req.Name)
	suite.Require().NoError(err)
	suite.Assert().Equal(req.Name, createdIssuer.IssuerType)
	suite.Assert().Equal(req.Cohort, createdIssuer.IssuerCohort)
	suite.Assert().Equal(req.MaxTokens, createdIssuer.MaxTokens)
	suite.Assert().Equal(2, createdIssuer.Version)
	// V3 fields should be zero/nil for v2
	suite.Assert().Equal(0, createdIssuer.Buffer)
	suite.Assert().Nil(createdIssuer.Duration)
}

// Test creating issuer without required name
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_MissingName() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	req := CreateIssuerRequest{
		Cohort:   1,
		Duration: "P1D",
		Buffer:   5,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test creating v3 issuer without required buffer
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V3_MissingBuffer() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	req := CreateIssuerRequest{
		Name:     test.RandomString(),
		Cohort:   1,
		Version:  3,
		Duration: "P1D",
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test creating v3 issuer without required duration
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V3_MissingDuration() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	req := CreateIssuerRequest{
		Name:    test.RandomString(),
		Cohort:  1,
		Version: 3,
		Buffer:  5,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_V3_InvalidDurationFormat() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	req := CreateIssuerRequest{
		Name:     test.RandomString(),
		Cohort:   1,
		Version:  3,
		Buffer:   5,
		Duration: "invalid-duration", // Invalid ISO 8601 duration
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.Require().NoError(err)
	suite.Assert().Contains(errResp["message"], "Invalid duration format")
}

// Test creating issuer with invalid version
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_InvalidVersion() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	req := CreateIssuerRequest{
		Name:    test.RandomString(),
		Cohort:  1,
		Version: 5, // Invalid version
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test creating issuer with past expiration
func (suite *ManageIssuersTestSuite) TestManageCreateIssuer_PastExpiration() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	pastTime := time.Now().Add(-24 * time.Hour)
	req := CreateIssuerRequest{
		Name:      test.RandomString(),
		Cohort:    1,
		Version:   3,
		ExpiresAt: &pastTime,
		Duration:  "P1D",
		Buffer:    5,
	}

	payload, err := json.Marshal(req)
	suite.Require().NoError(err)

	resp, err := suite.request("POST", server.URL+"/api/v1/manage/issuers", payload)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test deleting an issuer with force flag
func (suite *ManageIssuersTestSuite) TestManageDeleteIssuer_Force_Success() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Create an issuer
	issuer := model.Issuer{
		Version:      3,
		IssuerType:   test.RandomString(),
		IssuerCohort: 1,
		MaxTokens:    10,
		ExpiresAt:    pq.NullTime{Time: time.Now().Add(24 * time.Hour), Valid: true},
		Buffer:       1,
		Overlap:      0,
		Duration:     ptr.FromString("P1D"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}
	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	ctx := context.Background()
	createdIssuer, err := suite.srv.fetchIssuerByType(ctx, issuer.IssuerType)
	suite.Require().NoError(err)

	// Force delete
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s?force=true", server.URL, createdIssuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNoContent, resp.StatusCode)

	// Verify the issuer was deleted
	_, err = suite.srv.fetchIssuerByID(createdIssuer.ID.String())
	suite.Assert().Equal(errIssuerNotFound, err)
}

// Test deleting a non-existent issuer
func (suite *ManageIssuersTestSuite) TestManageDeleteIssuer_NotFound() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	randomID := uuid.New().String()
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s", server.URL, randomID), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNotFound, resp.StatusCode)
}

// Test deleting issuer with active keys without force flag
func (suite *ManageIssuersTestSuite) TestManageDeleteIssuer_ActiveKeys_Conflict() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Create an issuer with active keys
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

	// Try to delete without force flag - should fail due to active keys
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s", server.URL, createdIssuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode)
}

// Test force deleting issuer with active keys
func (suite *ManageIssuersTestSuite) TestManageDeleteIssuer_ActiveKeys_ForceDelete() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	// Create an issuer with active keys
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

	// Force delete
	resp, err := suite.request("DELETE", fmt.Sprintf("%s/api/v1/manage/issuers/%s?force=true", server.URL, createdIssuer.ID.String()), nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusNoContent, resp.StatusCode)

	// Verify the issuer was deleted
	_, err = suite.srv.fetchIssuerByID(createdIssuer.ID.String())
	suite.Assert().Equal(errIssuerNotFound, err)
}

// Test deleting issuer with invalid UUID format
func (suite *ManageIssuersTestSuite) TestManageDeleteIssuer_InvalidUUID() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	resp, err := suite.request("DELETE", server.URL+"/api/v1/manage/issuers/not-a-uuid", nil)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode)
}

// Test makeIssuerDetailResponse helper function
func (suite *ManageIssuersTestSuite) TestMakeIssuerDetailResponse() {
	id := uuid.New()
	createdAt := time.Now().Add(-24 * time.Hour)
	expiresAt := time.Now().Add(24 * time.Hour)
	validFrom := time.Now()
	duration := "P1D"

	issuer := &model.Issuer{
		ID:           &id,
		IssuerType:   "test-issuer",
		IssuerCohort: 5,
		MaxTokens:    100,
		Version:      3,
		CreatedAt:    pq.NullTime{Time: createdAt, Valid: true},
		ExpiresAt:    pq.NullTime{Time: expiresAt, Valid: true},
		ValidFrom:    &validFrom,
		Buffer:       10,
		Overlap:      2,
		Duration:     &duration,
		Keys:         []model.IssuerKeys{},
	}

	resp := makeIssuerDetailResponse(issuer)

	suite.Assert().Equal(id.String(), resp.ID)
	suite.Assert().Equal("test-issuer", resp.Name)
	suite.Assert().Equal(int16(5), resp.Cohort)
	suite.Assert().Equal(100, resp.MaxTokens)
	suite.Assert().Equal(3, resp.Version)
	suite.Assert().Equal(10, resp.Buffer)
	suite.Assert().Equal(2, resp.Overlap)
	suite.Assert().NotNil(resp.ExpiresAt)
	suite.Assert().NotNil(resp.CreatedAt)
	suite.Assert().NotNil(resp.ValidFrom)
	suite.Assert().Equal(&duration, resp.Duration)
}

// Test makeIssuerDetailResponse with nil/zero values
func (suite *ManageIssuersTestSuite) TestMakeIssuerDetailResponse_NilValues() {
	id := uuid.New()

	issuer := &model.Issuer{
		ID:           &id,
		IssuerType:   "test-issuer",
		IssuerCohort: 1,
		MaxTokens:    10,
		Version:      1,
		// CreatedAt, ExpiresAt, ValidFrom are nil/zero
	}

	resp := makeIssuerDetailResponse(issuer)

	suite.Assert().Equal(id.String(), resp.ID)
	suite.Assert().Nil(resp.ExpiresAt)
	suite.Assert().Nil(resp.CreatedAt)
	suite.Assert().Nil(resp.ValidFrom)
}
