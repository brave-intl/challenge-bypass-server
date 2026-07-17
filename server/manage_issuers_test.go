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
