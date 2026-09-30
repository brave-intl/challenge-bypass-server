//go:build db

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/stretchr/testify/suite"
)

type AdminHTTPSuite struct {
	suite.Suite
	srv    *Server
	http   *httptest.Server
	client *adminapi.Client
}

func TestAdminHTTPSuite(t *testing.T) { suite.Run(t, new(AdminHTTPSuite)) }

func (s *AdminHTTPSuite) SetupSuite() {
	s.Require().NoError(os.Setenv("ENV", "localtest"))
	priv, line := testOperatorKey(s.T(), "op@brave.com")
	devAdminKeys = []string{line}
	s.T().Cleanup(func() { devAdminKeys = nil })

	s.srv = &Server{}
	s.Require().NoError(s.srv.InitDBConfig())
	s.srv.InitDB(slog.New(slog.DiscardHandler))
	_, h := s.srv.setupRouter(SetupLogger(context.Background(), "t", "t", "t"))
	s.http = httptest.NewServer(h)
	s.T().Cleanup(s.http.Close)
	s.client = &adminapi.Client{BaseURL: s.http.URL, Key: priv}
}

func (s *AdminHTTPSuite) SetupTest() {
	for _, t := range []string{"issuer_admin_audit", "issuer_retirements", "v3_issuer_keys", "v3_issuers"} {
		_, err := s.srv.db.Exec("delete from " + t)
		s.Require().NoError(err)
	}
}

func (s *AdminHTTPSuite) TestLifecycle() {
	ctx := context.Background()
	old, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-old", Version: 1})
	s.Require().NoError(err)
	s.Equal(adminapi.StatusActive, old.Status)
	repl, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-new", Version: 1})
	s.Require().NoError(err)

	_, err = s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "h-old", Version: 1})
	s.apiErr(err, 409)

	list, err := s.client.ListIssuers(ctx)
	s.Require().NoError(err)
	s.Len(list, 2)

	start := time.Now().Add(time.Hour)
	_, err = s.client.RetireIssuer(ctx, old.ID, adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: start, StopRedeemingAt: start.Add(10 * 24 * time.Hour)})
	s.apiErr(err, 422)

	got, err := s.client.RetireIssuer(ctx, old.ID, adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: start, StopRedeemingAt: start.Add(91 * 24 * time.Hour)})
	s.Require().NoError(err)
	s.Equal(adminapi.StatusRetiring, got.Status)

	got, err = s.client.CancelRetirement(ctx, old.ID)
	s.Require().NoError(err)
	s.Equal(adminapi.StatusActive, got.Status)

	audit, err := s.client.ListAudit(ctx, old.ID, 5)
	s.Require().NoError(err)
	s.Equal([]string{"cancel_retire", "retire", "create"}, actions(audit))
	s.Equal("op@brave.com", audit[0].Operator)

	_, err = s.client.GetIssuer(ctx, "00000000-0000-0000-0000-000000000000")
	s.apiErr(err, 404)
	_, err = s.client.GetIssuer(ctx, "not-a-uuid")
	s.apiErr(err, 400)
}

func (s *AdminHTTPSuite) TestPatchRejectsUnknownFields() {
	ctx := context.Background()
	iss, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "p", Version: 1})
	s.Require().NoError(err)
	// raw request with an immutable field
	type raw struct {
		Buffer int `json:"buffer"`
	}
	err = s.clientDo("PATCH", "/v1/admin/issuers/"+iss.ID, raw{Buffer: 3})
	s.apiErr(err, 422)
}

func (s *AdminHTTPSuite) TestNoSigningKeysInResponses() {
	ctx := context.Background()
	iss, err := s.client.CreateIssuer(ctx, adminapi.CreateIssuerRequest{Name: "leak", Version: 1})
	s.Require().NoError(err)
	req, _ := http.NewRequest("GET", s.http.URL+"/v1/admin/issuers/"+iss.ID, nil)
	adminapi.SignRequest(req, nil, s.client.Key, time.Now())
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var sb strings.Builder
	_, _ = io.Copy(&sb, resp.Body)
	s.NotContains(sb.String(), "signing_key")
	var signing []byte
	s.Require().NoError(s.srv.db.QueryRow(`SELECT signing_key FROM v3_issuer_keys LIMIT 1`).Scan(&signing))
	s.NotContains(sb.String(), string(signing))
}

func (s *AdminHTTPSuite) TestUnsignedRejected() {
	resp, err := http.Get(s.http.URL + "/v1/admin/issuers")
	s.Require().NoError(err)
	s.Equal(401, resp.StatusCode)
}

func (s *AdminHTTPSuite) apiErr(err error, status int) {
	var ae *adminapi.APIError
	s.Require().ErrorAs(err, &ae)
	s.Equal(status, ae.Status, ae.Message)
}

// clientDo sends an arbitrary signed JSON body (for invalid-shape tests).
func (s *AdminHTTPSuite) clientDo(method, path string, body any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, s.http.URL+path, bytes.NewReader(b))
	adminapi.SignRequest(req, b, s.client.Key, time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &adminapi.APIError{Status: resp.StatusCode}
	}
	return nil
}

func actions(es []adminapi.AuditEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Action
	}
	return out
}
