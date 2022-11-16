package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"

	"github.com/brave-intl/challenge-bypass-server/utils/test"

	"github.com/brave-intl/bat-go/libs/middleware"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/go-chi/chi"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	handler     http.Handler
	accessToken string
	srv         *Server
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) SetupSuite() {
	err := os.Setenv("ENV", "localtest")
	suite.Require().NoError(err)

	suite.accessToken = uuid.NewV4().String()
	middleware.TokenList = []string{suite.accessToken}

	suite.srv = &Server{}

	err = suite.srv.InitDBConfig()
	suite.Require().NoError(err, "Failed to setup db conn")

	suite.handler = chi.ServerBaseContext(suite.srv.setupRouter(SetupLogger(context.Background())))

	suite.srv.InitDB()
	suite.srv.InitDynamo()

	err = test.SetupDynamodbTables(suite.srv.dynamo)
	suite.Require().NoError(err)

	suite.handler = chi.ServerBaseContext(suite.srv.setupRouter(SetupLogger(context.Background())))
}

func (suite *ServerTestSuite) SetupTest() {
	tables := []string{"v3_issuer_keys", "v3_issuers", "redemptions"}

	for _, table := range tables {
		_, err := suite.srv.db.Exec("delete from " + table)
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
	actual, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err, "Reading response body should succeed")
	suite.Assert().Equal(expected, string(actual), "Message should match")
}

func (suite *ServerTestSuite) TestIssueRedeem() {
	issuerType := "test"
	issuerCohort := v1Cohort
	msg := "test message"

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	publicKey := suite.createIssuer(server.URL, issuerType, issuerCohort)
	unblindedToken := suite.createToken(server.URL, issuerType, publicKey)
	preimageText, sigText := suite.prepareRedemption(unblindedToken, msg)

	resp, err := suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	resp, err = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode, "Attempted duplicate redemption request should fail")
}

func (suite *ServerTestSuite) TestIssuerGetAll() {
	issuerType := "test2"
	issuerCohort := v1Cohort

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().AddDate(0, 0, 1)
	suite.createIssuerWithExpiration(server.URL, issuerType, issuerCohort, expiresAt)
	issuers := suite.getAllIssuers(server.URL)

	suite.Assert().Equal(reflect.ValueOf(issuers).Len(), 1, "Exactly one issuer")
}

func (suite *ServerTestSuite) TestIssueRedeemV2() {
	issuerType := "test2"
	issuerCohort := v1Cohort
	msg := "test message 2"

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().AddDate(0, 0, 1)
	publicKey := suite.createIssuerWithExpiration(server.URL, issuerType, issuerCohort, expiresAt)
	issuer, _ := suite.srv.GetLatestIssuer(issuerType, issuerCohort)

	unblindedToken := suite.createToken(server.URL, issuerType, publicKey)
	preimageText, sigText := suite.prepareRedemption(unblindedToken, msg)
	resp, err := suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Redemption response body read must succeed")

	var issuerResp blindedTokenRedeemResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Redemption response body unmarshal must succeed")
	suite.Assert().Equal(issuerResp.Cohort, issuerCohort, "Redemption of a token should return the same cohort with which it was signed")

	resp, err = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode, "Attempted duplicate redemption request should fail")

	unblindedToken = suite.createToken(server.URL, issuerType, publicKey)
	preimageText, sigText = suite.prepareRedemption(unblindedToken, msg)
	unblindedToken2 := suite.createToken(server.URL, issuerType, publicKey)
	preimageText2, sigText2 := suite.prepareRedemption(unblindedToken2, msg)
	// should create a new key in keys table
	_ = suite.srv.rotateIssuers()
	resp, _ = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	body, err = io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Redemption response body read must succeed")

	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Redemption response body unmarshal must succeed")
	suite.Assert().NotEqual(issuerResp.Cohort, 1-issuerCohort, "Redemption of a token should return the same cohort with which it was signed")
	r, err := suite.srv.db.Query(`UPDATE v3_issuers SET expires_at=$1 WHERE issuer_id=$2`, time.Now().AddDate(0, 0, -1), issuer.ID)
	suite.Require().NoError(err, "failed to expire issuer")
	defer r.Close()
	// keys are what rotate now, not the issuer itself
	issuer, _ = suite.srv.GetLatestIssuer(issuerType, issuerCohort)

	resp, err = suite.attemptRedeem(server.URL, preimageText2, sigText2, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode, "Expired Issuers should fail")

	// get public key from issuer keys
	var signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
	publicKey = signingKey.PublicKey()

	r, err = suite.srv.db.Query(`UPDATE v3_issuers SET expires_at=$1 WHERE issuer_id=$2`, time.Now().AddDate(0, 0, +1), issuer.ID)
	suite.Require().NoError(err, "failed to unexpire issuer")
	defer r.Close()

	unblindedToken = suite.createToken(server.URL, issuerType, publicKey)
	preimageText, sigText = suite.prepareRedemption(unblindedToken, msg)
	resp, err = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")
}

func (suite *ServerTestSuite) TestNewIssueRedeemV2() {
	issuerType := "test2"
	issuerCohort := v1Cohort
	msg := "test message 2"

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	expiresAt := time.Now().AddDate(0, 0, 1)
	publicKey := suite.createIssuerWithExpiration(server.URL, issuerType, issuerCohort, expiresAt)
	issuer, _ := suite.srv.GetLatestIssuer(issuerType, issuerCohort)

	unblindedToken := suite.createCohortToken(server.URL, issuerType, issuerCohort, publicKey)
	preimageText, sigText := suite.prepareRedemption(unblindedToken, msg)
	resp, err := suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Redemption response body read must succeed")

	var issuerResp blindedTokenRedeemResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Redemption response body unmarshal must succeed")
	suite.Assert().Equal(issuerResp.Cohort, issuerCohort, "Redemption of a token should return the same cohort with which it was signed")

	resp, err = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode, "Attempted duplicate redemption request should fail")

	unblindedToken = suite.createCohortToken(server.URL, issuerType, issuerCohort, publicKey)
	preimageText, sigText = suite.prepareRedemption(unblindedToken, msg)
	unblindedToken2 := suite.createCohortToken(server.URL, issuerType, issuerCohort, publicKey)
	preimageText2, sigText2 := suite.prepareRedemption(unblindedToken2, msg)
	_ = suite.srv.rotateIssuers()
	resp, _ = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	body, err = io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Redemption response body read must succeed")

	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Redemption response body unmarshal must succeed")
	suite.Assert().NotEqual(issuerResp.Cohort, 1-issuerCohort, "Redemption of a token should return the same cohort with which it was signed")

	r, err := suite.srv.db.Query(`UPDATE v3_issuers SET expires_at=$1 WHERE issuer_id=$2`, time.Now().AddDate(0, 0, -1), issuer.ID)
	suite.Require().NoError(err, "failed to expire issuer")
	defer r.Close()

	resp, err = suite.attemptRedeem(server.URL, preimageText2, sigText2, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusBadRequest, resp.StatusCode, "Expired Issuers should fail")
}

type v3Redemption struct {
	validFrom       time.Time
	validTo         time.Time
	unblindedTokens []*crypto.UnblindedToken
}

func (suite *ServerTestSuite) TestRotateTimeAwareIssuer() {
	var buffer = 3
	var issuerType = test.RandomString()
	issuer := Issuer{
		Version:      3,
		IssuerType:   issuerType,
		IssuerCohort: 1,
		MaxTokens:    buffer,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Buffer:       buffer,
		Overlap:      0,
		Duration:     ptr.FromString("PT1S"), // an issuer exists every 3 seconds
		ValidFrom:    ptr.FromTime(time.Now()),
	}

	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	// wait a few intervals after creation and check number of signing keys left
	time.Sleep(2 * time.Second)
	myIssuer, err := suite.srv.GetLatestIssuer(issuer.IssuerType, issuer.IssuerCohort)
	fmt.Println(err)
	suite.Require().Equal(len(myIssuer.Keys), 1) // should be one left

	// rotate issuers should pick up that there are some new intervals to make up buffer and populate
	err = suite.srv.rotateIssuersV3()
	suite.Require().NoError(err)

	myIssuer, err = suite.srv.GetLatestIssuer(issuer.IssuerType, issuer.IssuerCohort)
	suite.Require().NoError(err)
	suite.Require().Equal(len(myIssuer.Keys), 3) // should be 3 now

	// rotate issuers should pick up that there are some new intervals to make up buffer and populate
	err = suite.srv.rotateIssuersV3()
	suite.Require().NoError(err)
	suite.Require().Equal(len(myIssuer.Keys), 3) // should be 3 now still

	// wait a few intervals after creation and check number of signing keys left
	time.Sleep(2 * time.Second)
	myIssuer, err = suite.srv.GetLatestIssuer(issuer.IssuerType, issuer.IssuerCohort)
	suite.Require().NoError(err)
	suite.Require().Equal(len(myIssuer.Keys), 1) // should be one left
}

func (suite *ServerTestSuite) TestCreateIssuerV3() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	ctx := context.Background()

	request := issuerV3CreateRequest{
		Name:      test.RandomString(),
		Cohort:    3,
		MaxTokens: 10,
		ValidFrom: ptr.FromTime(time.Now()),
		Duration:  "P1M",
		Buffer:    10,
		Overlap:   2,
	}

	payload, err := json.Marshal(request)
	suite.Require().NoError(err)

	createIssuerURL := fmt.Sprintf("%s/v3/issuer/", server.URL)
	resp, err := suite.request("POST", createIssuerURL, bytes.NewBuffer(payload))
	suite.Require().NoError(err)

	suite.Assert().Equal(http.StatusCreated, resp.StatusCode)

	actualIssuer, err := suite.srv.fetchIssuerByType(ctx, request.Name)
	suite.Require().NoError(err)

	suite.Assert().Equal(request.Name, actualIssuer.IssuerType)
	suite.Assert().Equal(request.Cohort, actualIssuer.IssuerCohort)
	suite.Assert().Equal(request.MaxTokens, actualIssuer.MaxTokens)
	suite.Assert().Equal(request.MaxTokens, actualIssuer.MaxTokens)
	suite.Assert().WithinDuration(*request.ValidFrom, *actualIssuer.ValidFrom, 100*time.Millisecond)
	suite.Assert().Equal(request.Duration, *actualIssuer.Duration)
	suite.Assert().Equal(request.Buffer, actualIssuer.Buffer)
	suite.Assert().Equal(request.Overlap, actualIssuer.Overlap)
}

func (suite *ServerTestSuite) TestGetIssuerV2() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()

	var issuerType = test.RandomString()
	issuer := Issuer{
		Version:      3,
		IssuerType:   issuerType,
		IssuerCohort: 1,
		MaxTokens:    1,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Buffer:       1,
		Overlap:      1,
		Duration:     ptr.FromString("PT10S"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}

	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	request := issuerFetchRequestV2{
		issuer.IssuerCohort,
	}

	payload, err := json.Marshal(request)
	suite.Require().NoError(err)

	url := fmt.Sprintf("%s/v2/issuer/%s", server.URL, issuer.IssuerType)
	resp, err := suite.request(http.MethodGet, url, bytes.NewBuffer(payload))
	suite.Require().NoError(err)

	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	var actual issuerResponse
	err = json.NewDecoder(resp.Body).Decode(&actual)
	suite.Require().NoError(err)

	suite.Assert().Equal(issuer.IssuerType, actual.Name)
}

func (suite *ServerTestSuite) TestDeleteIssuerKeysV3() {
	issuer := Issuer{
		Version:      3,
		IssuerType:   test.RandomString(),
		IssuerCohort: 1,
		MaxTokens:    5,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Buffer:       4,
		Overlap:      0,
		Duration:     ptr.FromString("PT1S"),
		ValidFrom:    ptr.FromTime(time.Now()),
	}

	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	time.Sleep(2 * time.Second)

	rows, err := suite.srv.deleteIssuerKeys("PT1S")
	suite.Require().NoError(err)

	suite.Assert().Equal(int64(1), rows)
}

func (suite *ServerTestSuite) TestRunRotate() {
	err := suite.srv.rotateIssuersV3()
	suite.Require().NoError(err)
}

func (suite *ServerTestSuite) request(method string, url string, payload io.Reader) (*http.Response, error) {
	var req *http.Request
	var err error
	if payload != nil {
		req, err = http.NewRequest(method, url, payload)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+suite.accessToken)
	req.Header.Add("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func (suite *ServerTestSuite) createIssuer(serverURL string, issuerType string, issuerCohort int16) *crypto.PublicKey {
	payload := fmt.Sprintf(`{"name":"%s", "cohort": %d, "max_tokens":100}`, issuerType, issuerCohort)
	createIssuerURL := fmt.Sprintf("%s/v1/issuer/", serverURL)
	resp, err := suite.request("POST", createIssuerURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Issuer creation must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	payload = fmt.Sprintf(`{"cohort": %d}`, issuerCohort)
	issuerURL := fmt.Sprintf("%s/v2/issuer/%s", serverURL, issuerType)
	resp, err = suite.request("GET", issuerURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Issuer fetch must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Issuer fetch body read must succeed")

	var issuerResp issuerResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Issuer fetch body unmarshal must succeed")

	suite.Require().NotEqual(issuerResp.PublicKey, nil, "Public key was missing")

	suite.Require().NotEqual(issuerResp.ID, "", "ID was missing")

	return issuerResp.PublicKey
}

func (suite *ServerTestSuite) getAllIssuers(serverURL string) []issuerResponse {
	getAllIssuersURL := fmt.Sprintf("%s/v1/issuer/", serverURL)
	resp, err := suite.request("GET", getAllIssuersURL, nil)
	suite.Require().NoError(err, "Getting alll Issuers must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Issuer fetch body read must succeed")

	var issuerResp []issuerResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Issuer fetch body unmarshal must succeed")

	suite.Require().NotEqual(issuerResp[0].ID, "", "ID was missing")
	suite.Require().NotEqual(issuerResp[0].Name, "", "Name was missing")
	suite.Require().NotEqual(issuerResp[0].PublicKey, "", "Public Key was missing")
	suite.Require().NotEqual(issuerResp[0].Cohort, "", "Cohort was missing")

	return issuerResp
}

func (suite *ServerTestSuite) createIssuerWithExpiration(serverURL string, issuerType string, issuerCohort int16, expiresAt time.Time) *crypto.PublicKey {
	payload := fmt.Sprintf(`{"name":"%s", "cohort": %d, "max_tokens":100, "expires_at":"%s"}`, issuerType, issuerCohort, expiresAt.Format("2006-01-02T15:04:05Z07:00"))
	// v2+ has expirations
	createIssuerURL := fmt.Sprintf("%s/v2/issuer/", serverURL)
	resp, err := suite.request("POST", createIssuerURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Issuer creation must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	payload = fmt.Sprintf(`{"cohort": %d}`, issuerCohort)
	issuerURL := fmt.Sprintf("%s/v2/issuer/%s", serverURL, issuerType)
	resp, err = suite.request("GET", issuerURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Issuer fetch must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Issuer fetch body read must succeed")

	var issuerResp issuerResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Issuer fetch body unmarshal must succeed")

	suite.Require().NotEqual(issuerResp.PublicKey, nil, "Public key was missing")
	suite.Require().NotEqual(issuerResp.Cohort, nil, "Public key was missing")

	suite.Require().NotEqual(issuerResp.ID, "", "ID was missing")

	return issuerResp.PublicKey
}

func (suite *ServerTestSuite) createToken(serverURL string, issuerType string, publicKey *crypto.PublicKey) *crypto.UnblindedToken {
	return suite.createTokens(serverURL, issuerType, publicKey, 1)[0]
}

func (suite *ServerTestSuite) createTokens(serverURL string, issuerType string, publicKey *crypto.PublicKey, numTokens int) []*crypto.UnblindedToken {
	tokens := make([]*crypto.Token, numTokens)
	blindedTokens := make([]*crypto.BlindedToken, numTokens)

	for i := 0; i < numTokens; i++ {
		token, err := crypto.RandomToken()
		suite.Require().NoError(err, "Must be able to generate random token")
		tokens[i] = token

		blindedToken := token.Blind()
		suite.Require().NoError(err, "Must be able to blind token")
		blindedTokens[i] = blindedToken
	}

	blindedTokenText, err := json.Marshal(blindedTokens)
	suite.Require().NoError(err, "Must be able to marshal blinded tokens")

	payload := fmt.Sprintf(`{"blinded_tokens":%s}}`, blindedTokenText)
	issueURL := fmt.Sprintf("%s/v1/blindedToken/%s", serverURL, issuerType)
	resp, err := suite.request("POST", issueURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Token signing must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Token signing body read must succeed")

	var decodedResp blindedTokenIssueResponse
	err = json.Unmarshal(body, &decodedResp)
	suite.Require().NoError(err, "Token signing body unmarshal must succeed")

	suite.Require().NotEqual(nil, decodedResp.BatchProof, "Batch proof was missing")
	suite.Require().Equal(numTokens, len(decodedResp.SignedTokens), "Signed tokens were missing")

	unblindedTokens, err := decodedResp.BatchProof.VerifyAndUnblind(tokens, blindedTokens, decodedResp.SignedTokens, publicKey)
	suite.Require().NoError(err, "Batch verification and token unblinding must succeed")

	return unblindedTokens
}

func (suite *ServerTestSuite) prepareRedemption(unblindedToken *crypto.UnblindedToken, msg string) (preimageText []byte, sigText []byte) {
	vKey := unblindedToken.DeriveVerificationKey()

	sig, err := vKey.Sign(msg)
	suite.Require().NoError(err, "Must be able to sign message")
	sigText, err = sig.MarshalText()
	suite.Require().NoError(err, "Must be able to marshal signature")

	preimage := unblindedToken.Preimage()
	preimageText, err = preimage.MarshalText()
	suite.Require().NoError(err, "Must be able to marshal preimage")

	return
}

func (suite *ServerTestSuite) attemptRedeem(serverURL string, preimageText []byte, sigText []byte, issuerType string, msg string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"t":"%s", "signature":"%s", "payload":"%s"}`, preimageText, sigText, msg)
	redeemURL := fmt.Sprintf("%s/v1/blindedToken/%s/redemption/", serverURL, issuerType)

	return suite.request("POST", redeemURL, bytes.NewBuffer([]byte(payload)))
}

func (suite *ServerTestSuite) createCohortToken(serverURL string, issuerType string, issuerCohort int16, publicKey *crypto.PublicKey) *crypto.UnblindedToken {
	return suite.createCohortTokens(serverURL, issuerType, issuerCohort, publicKey, 1)[0]
}

func (suite *ServerTestSuite) createCohortTokens(serverURL string, issuerType string, issuerCohort int16, publicKey *crypto.PublicKey, numTokens int) []*crypto.UnblindedToken {
	tokens := make([]*crypto.Token, numTokens)
	blindedTokens := make([]*crypto.BlindedToken, numTokens)

	for i := 0; i < numTokens; i++ {
		token, err := crypto.RandomToken()
		suite.Require().NoError(err, "Must be able to generate random token")
		tokens[i] = token

		blindedToken := token.Blind()
		suite.Require().NoError(err, "Must be able to blind token")
		blindedTokens[i] = blindedToken
	}

	blindedTokenText, err := json.Marshal(blindedTokens)
	suite.Require().NoError(err, "Must be able to marshal blinded tokens")

	payload := fmt.Sprintf(`{"blinded_tokens":%s, "cohort":%d}}`, blindedTokenText, issuerCohort)
	issueURL := fmt.Sprintf("%s/v2/blindedToken/%s", serverURL, issuerType)
	resp, err := suite.request("POST", issueURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Token signing must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err, "Token signing body read must succeed")

	var decodedResp blindedTokenIssueResponse
	err = json.Unmarshal(body, &decodedResp)
	suite.Require().NoError(err, "Token signing body unmarshal must succeed")

	suite.Require().NotEqual(nil, decodedResp.BatchProof, "Batch proof was missing")
	suite.Require().Equal(numTokens, len(decodedResp.SignedTokens), "Signed tokens were missing")

	unblindedTokens, err := decodedResp.BatchProof.VerifyAndUnblind(tokens, blindedTokens, decodedResp.SignedTokens, publicKey)
	suite.Require().NoError(err, "Batch verification and token unblinding must succeed")

	return unblindedTokens
}

func (suite *ServerTestSuite) TestRedeemV3() {
	var buffer = 10
	var redemptions = []v3Redemption{}
	var issuerType = test.RandomString()
	issuer := Issuer{
		Version:      3,
		IssuerType:   issuerType,
		IssuerCohort: 1,
		MaxTokens:    buffer,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Buffer:       buffer,
		Overlap:      0,
		Duration:     ptr.FromString("PT1S"), // an issuer exists every 3 seconds
		ValidFrom:    ptr.FromTime(time.Now()),
	}

	err := suite.srv.createV3Issuer(issuer)
	suite.Require().NoError(err)

	issuerKey, err := suite.srv.GetLatestIssuer(issuer.IssuerType, issuer.IssuerCohort)
	fmt.Println(err)

	tokens := make([]*crypto.Token, buffer)
	blindedTokensSlice := make([]*crypto.BlindedToken, buffer)

	for i := 0; i < buffer; i++ {
		token, err := crypto.RandomToken()
		suite.Require().NoError(err, "Must be able to generate random token")

		blindedToken := token.Blind()
		suite.Require().NoError(err, "Must be able to blind token")

		tokens[i] = token
		blindedTokensSlice[i] = blindedToken
	}

	server := httptest.NewServer(suite.handler)
	defer server.Close()
	var count = 0
	for i := 0; i < buffer; i++ {
		count++
		var (
			signingKey *crypto.SigningKey
			validFrom  *time.Time
			validTo    *time.Time
		)

		signingKey = issuerKey.Keys[len(issuerKey.Keys)-count].SigningKey
		validFrom = issuerKey.Keys[len(issuerKey.Keys)-count].StartAt
		validTo = issuerKey.Keys[len(issuerKey.Keys)-count].EndAt

		// sign some tokens
		signedTokens, DLEQProof, err := btd.ApproveTokens(
			[]*crypto.BlindedToken{blindedTokensSlice[i]},
			signingKey)
		suite.Require().NoError(err, "Must be able to approve token")

		unblindedTokens, err := DLEQProof.VerifyAndUnblind(
			[]*crypto.Token{tokens[i]}, []*crypto.BlindedToken{blindedTokensSlice[i]},
			signedTokens, signingKey.PublicKey())

		suite.Require().NoError(err, "Must be able to verify and unblind")

		redemptions = append(redemptions, v3Redemption{
			validFrom: *validFrom, validTo: *validTo, unblindedTokens: unblindedTokens,
		})
	}

	for i := 0; i < buffer; i++ {
		var unblindedToken *crypto.UnblindedToken
		for _, v := range redemptions {
			if v.validFrom.Before(time.Now()) && v.validTo.After(time.Now()) {
				unblindedToken = v.unblindedTokens[0]
			}
		}
		msg := "test message"
		preimageText, sigText := suite.prepareRedemption(unblindedToken, msg) // only 1 per time interval

		payload := fmt.Sprintf(`{"t":"%s", "signature":"%s", "payload":"%s"}`, preimageText, sigText, msg)
		redeemURL := fmt.Sprintf("%s/v3/blindedToken/%s/redemption/", server.URL, issuerType)

		response, err := suite.request(http.MethodPost, redeemURL, bytes.NewBuffer([]byte(payload)))
		suite.Require().NoError(err)

		suite.Require().Equal(http.StatusOK, response.StatusCode)
		time.Sleep(1 * time.Second) // wait for next interval to start
	}
}
