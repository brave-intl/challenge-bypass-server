//go:build db

package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

type AdminDBSuite struct {
	suite.Suite
	srv *Server
	ctx context.Context
}

func TestAdminDBSuite(t *testing.T) { suite.Run(t, new(AdminDBSuite)) }

func (s *AdminDBSuite) SetupSuite() {
	s.srv = &Server{}
	s.Require().NoError(s.srv.InitDBConfig())
	s.srv.InitDB(slog.New(slog.DiscardHandler))
	s.srv.Logger = slog.New(slog.DiscardHandler)
	s.ctx = context.Background()
}

func (s *AdminDBSuite) SetupTest() {
	for _, t := range []string{"issuer_admin_audit", "issuer_retirements", "v3_issuer_keys", "v3_issuers"} {
		_, err := s.srv.db.Exec("delete from " + t)
		s.Require().NoError(err)
	}
}

func (s *AdminDBSuite) create(req adminapi.CreateIssuerRequest) uuid.UUID {
	id, err := s.srv.adminCreateIssuer(s.ctx, "op@brave.com", req)
	s.Require().NoError(err)
	return id
}

func v1(name string) adminapi.CreateIssuerRequest {
	return adminapi.CreateIssuerRequest{Name: name, Version: 1, Cohort: 1}
}

func v3(name string, expires time.Time) adminapi.CreateIssuerRequest {
	return adminapi.CreateIssuerRequest{Name: name, Version: 3, Cohort: 1, Duration: "P2M",
		Buffer: 2, Overlap: 1, ExpiresAt: &expires}
}

func (s *AdminDBSuite) TestCreateAndReadWritesAudit() {
	id := s.create(v1("ads-a"))

	got, err := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Require().NoError(err)
	s.Equal("ads-a", got.Name)
	s.Equal(1, got.Version)
	s.Equal(adminapi.StatusActive, got.Status)
	s.Nil(got.ExpiresAt, "0001-01-01 sentinel must read as no expiry")
	s.Len(got.Keys, 1)
	s.NotEmpty(got.Keys[0].ID)
	s.NotEmpty(got.Keys[0].PublicKey)

	list, err := s.srv.adminListIssuers(s.ctx, time.Now())
	s.Require().NoError(err)
	s.Len(list, 1)
	s.Equal(1, list[0].KeyCount)
	s.Empty(list[0].Keys, "list does not embed keys")

	audit, err := s.srv.adminListAudit(s.ctx, &id, 10)
	s.Require().NoError(err)
	s.Require().Len(audit, 1)
	s.Equal("create", audit[0].Action)
	s.Equal("op@brave.com", audit[0].Operator)
}

func (s *AdminDBSuite) TestCreateV3PopulatesWindows() {
	id := s.create(v3("skus-a", time.Now().AddDate(1, 0, 0)))
	got, err := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Require().NoError(err)
	s.Len(got.Keys, 3) // buffer + overlap
	s.NotNil(got.LatestKeyEnd)
}

func (s *AdminDBSuite) TestCreateDuplicateRollsBackAudit() {
	s.create(v1("dup"))
	_, err := s.srv.adminCreateIssuer(s.ctx, "op@brave.com", v1("dup"))
	s.Require().Error(err)
	audit, err := s.srv.adminListAudit(s.ctx, nil, 10)
	s.Require().NoError(err)
	s.Len(audit, 1, "failed create must not leave an audit row")
}

func (s *AdminDBSuite) TestCreateValidation() {
	for _, req := range []adminapi.CreateIssuerRequest{
		{Name: "", Version: 1},
		{Name: "x", Version: 4},
		{Name: "x", Version: 3, Duration: "", Buffer: 1},
		{Name: "x", Version: 3, Duration: "P1M", Buffer: 0},
		{Name: "x", Version: 1, ExpiresAt: ptrTime(time.Now().Add(-time.Hour))},
	} {
		_, err := s.srv.adminCreateIssuer(s.ctx, "op", req)
		var re *adminRuleError
		s.ErrorAs(err, &re, "%+v", req)
	}
}

func (s *AdminDBSuite) TestGetUnknown() {
	_, err := s.srv.adminGetIssuer(s.ctx, uuid.New(), time.Now())
	s.ErrorIs(err, errAdminNotFound)
}

func ptrTime(t time.Time) *time.Time { return &t }

const day = 24 * time.Hour

func (s *AdminDBSuite) retire(id, repl uuid.UUID, stopIssuing, stopRedeeming time.Time) error {
	return s.srv.adminRetireIssuer(s.ctx, "op@brave.com", id, adminapi.RetireRequest{
		ReplacementIssuerID: repl.String(), StopIssuingAt: stopIssuing, StopRedeemingAt: stopRedeeming,
	}, time.Now())
}

func (s *AdminDBSuite) isRule(err error, contains string) {
	var re *adminRuleError
	s.Require().ErrorAs(err, &re)
	s.Contains(re.msg, contains)
}

func (s *AdminDBSuite) TestRetireHappyPathAndCancel() {
	old, repl := s.create(v1("old")), s.create(v1("new"))
	start := time.Now().Add(time.Hour)
	s.Require().NoError(s.retire(old, repl, start, start.Add(93*day)))

	got, _ := s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Equal(adminapi.StatusRetiring, got.Status)
	s.Equal(repl.String(), *got.ReplacementID)
	s.WithinDuration(start.Add(93*day), *got.ExpiresAt, time.Second)
	r, _ := s.srv.adminGetIssuer(s.ctx, repl, time.Now())
	s.Equal([]string{old.String()}, r.Replaces)

	s.Require().NoError(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now()))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Equal(adminapi.StatusActive, got.Status)
	s.Nil(got.ExpiresAt, "cancel restores the no-expiry sentinel")

	audit, _ := s.srv.adminListAudit(s.ctx, &old, 10)
	s.Equal("cancel_retire", audit[0].Action)
	s.Equal("retire", audit[1].Action)
}

func (s *AdminDBSuite) TestRetireRules() {
	now := time.Now()
	old, repl := s.create(v1("old")), s.create(v1("new"))
	start := now.Add(time.Minute)

	s.isRule(s.retire(old, old, start, start.Add(93*day)), "replacement")
	s.ErrorIs(s.retire(old, uuid.New(), start, start.Add(93*day)), errAdminNotFound)
	s.isRule(s.retire(old, repl, now.Add(-time.Hour), now.Add(93*day)), "stop_issuing_at")
	s.isRule(s.retire(old, repl, start, start.Add(89*day)), "90 days")

	// replacement expiring inside the overlap
	shortRepl := s.create(adminapi.CreateIssuerRequest{Name: "short", Version: 1, ExpiresAt: ptrTime(now.Add(30 * day))})
	s.isRule(s.retire(old, shortRepl, start, start.Add(93*day)), "replacement expires")

	// replacement that is itself retiring (Review Focus 1)
	third := s.create(v1("third"))
	s.Require().NoError(s.retire(repl, third, start, start.Add(93*day)))
	s.isRule(s.retire(old, repl, start, start.Add(93*day)), "replacement must be active")

	// already retiring target
	s.isRule(s.retire(repl, third, start, start.Add(93*day)), "already")
}

func (s *AdminDBSuite) TestRetireV3CoversFutureWindows() {
	old := s.create(v3("v3old", time.Now().AddDate(2, 0, 0))) // P2M, buffer 2, overlap 1
	repl := s.create(v1("v3new"))
	start := time.Now().Add(time.Minute)
	// 91 days < start + 6 months of windows → rejected
	s.isRule(s.retire(old, repl, start, start.Add(93*day)), "key window")
	s.Require().NoError(s.retire(old, repl, start, start.AddDate(0, 6, 2)))
}

func (s *AdminDBSuite) TestRetireReplacementNotYetValid() {
	old := s.create(v1("o"))
	later := time.Now().Add(10 * day)
	repl := s.create(adminapi.CreateIssuerRequest{Name: "r", Version: 3, Duration: "P1M", Buffer: 1,
		ValidFrom: &later, ExpiresAt: ptrTime(time.Now().AddDate(2, 0, 0))})
	start := time.Now().Add(time.Minute)
	s.isRule(s.retire(old, repl, start, start.Add(93*day)), "valid_from")
}

func (s *AdminDBSuite) TestChainRule() {
	a, b, c := s.create(v1("a")), s.create(v1("b")), s.create(v1("c"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(a, b, start, start.Add(100*day)))
	// b may not stop issuing before a stops redeeming
	s.isRule(s.retire(b, c, start.Add(time.Hour), start.Add(200*day)), "overlap promised")
	s.Require().NoError(s.retire(b, c, start.Add(100*day), start.Add(200*day)))
}

// The chain rule compares a timestamp-without-zone column with now; a
// non-UTC now used to be read hours off and skip the promise.
func (s *AdminDBSuite) TestChainRuleWithNonUTCNow() {
	a, b, c := s.create(v1("ca")), s.create(v1("cb")), s.create(v1("cc"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(a, b, start, start.Add(100*day)))
	promise := time.Now().Add(2 * time.Hour)
	_, err := s.srv.db.Exec(`UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, a, promise.UTC())
	s.Require().NoError(err)
	ahead := time.Now().In(time.FixedZone("UTC+5", 5*3600))
	err = s.srv.adminRetireIssuer(s.ctx, "op", b, adminapi.RetireRequest{
		ReplacementIssuerID: c.String(), StopIssuingAt: start, StopRedeemingAt: start.Add(100 * day),
	}, ahead)
	s.isRule(err, "overlap promised")
}

// The minimum is 3 calendar months when that is longer than 90 days
// (Nov 1 + 90 days = Jan 30, + 3 months = Feb 1).
func (s *AdminDBSuite) TestRetireNeedsThreeCalendarMonths() {
	old, repl := s.create(v1("m3-old")), s.create(v1("m3-new"))
	stop := time.Date(time.Now().Year()+1, 11, 1, 0, 0, 0, 0, time.UTC)
	s.isRule(s.retire(old, repl, stop, stop.Add(90*day)), "3 months")
	s.Require().NoError(s.retire(old, repl, stop, stop.AddDate(0, 3, 0)))
}

// With caching on, pods keep signing from a cached copy for up to the cache
// period after "retire now", so the overlap is measured from then.
func (s *AdminDBSuite) TestRetireNowCountsCachePeriod() {
	old, repl := s.create(v1("cache-old")), s.create(v1("cache-new"))
	saved := s.srv.dbConfig.CachingConfig
	s.srv.dbConfig.CachingConfig = CachingConfig{Enabled: true, ExpirationSec: 3600}
	defer func() { s.srv.dbConfig.CachingConfig = saved }()
	now := time.Now()
	s.isRule(s.retire(old, repl, now, adminapi.MinStopRedeeming(now).Add(time.Minute)), "last possible issuance")
	s.Require().NoError(s.retire(old, repl, now, adminapi.MinStopRedeeming(now.Add(time.Hour)).Add(time.Minute)))
}

// Postpone keeps 3 calendar months too, on both the explicit and the
// default stop_redeeming_at.
func (s *AdminDBSuite) TestPostponeNeedsThreeCalendarMonths() {
	old, repl := s.create(v1("pm3-old")), s.create(v1("pm3-new"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(old, repl, start, start.Add(93*day)))
	newStop := time.Date(time.Now().Year()+1, 11, 1, 0, 0, 0, 0, time.UTC)
	short := newStop.Add(90 * day)
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop, StopRedeemingAt: &short}, time.Now()), "3 months")
	s.Require().NoError(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop}, time.Now()))
	got, _ := s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.False(got.ExpiresAt.Before(newStop.AddDate(0, 3, 0)), "default redeem %s must reach 3 months after %s", got.ExpiresAt, newStop)
}

// Admin-created v3 issuers store valid_from at the right instant. Only
// meaningful with a non-UTC TZ: go test -run TestAdminDBSuite/TestCreateV3ValidFromIsUTC with TZ=America/New_York.
func (s *AdminDBSuite) TestCreateV3ValidFromIsUTC() {
	id := s.create(v3("vf3", time.Now().AddDate(1, 0, 0)))
	got, err := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Require().NoError(err)
	s.WithinDuration(time.Now(), *got.ValidFrom, time.Minute)
}

// The sign path loads retirement for every row in one query; a v3 issuer
// has one row per key.
func (s *AdminDBSuite) TestSignPathSeesRetirementWithManyKeys() {
	old := s.create(v3("many", time.Now().AddDate(2, 0, 0)))
	repl := s.create(v1("keys-repl"))
	var keys int
	s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM v3_issuer_keys WHERE issuer_id = $1`, old).Scan(&keys))
	s.Require().Greater(keys, 1)
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().AddDate(0, 7, 0)))
	k, err := s.srv.GetLatestIssuerKafka("many", 1)
	s.Require().NoError(err)
	s.False(k.IsIssuing(time.Now().Add(time.Second)))
}

func (s *AdminDBSuite) TestCancelAfterStopIssuingRejected() {
	old, repl := s.create(v1("o2")), s.create(v1("r2"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(93*day)))
	s.isRule(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now().Add(time.Second)), "only while retiring")
}

func (s *AdminDBSuite) TestPostponeResumesIssuing() {
	old, repl := s.create(v1("pp-old")), s.create(v1("pp-new"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(93*day)))
	later := time.Now().Add(time.Second)
	got, _ := s.srv.adminGetIssuer(s.ctx, old, later)
	s.Require().Equal(adminapi.StatusRetired, got.Status)
	before := *got.ExpiresAt

	newStop := time.Now().Add(30 * day)
	s.Require().NoError(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop}, later))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, later)
	s.Equal(adminapi.StatusRetiring, got.Status, "issuing again")
	s.WithinDuration(newStop, *got.StopIssuingAt, time.Second)
	s.False(got.ExpiresAt.Before(adminapi.MinStopRedeeming(newStop).Add(-time.Second)), "redeem window pushed to keep 3 months")
	s.False(got.ExpiresAt.Before(before), "never shortens")

	iss, appErr := s.srv.GetLatestIssuer("pp-old", v1Cohort)
	s.Require().Nil(appErr)
	s.True(iss.IsIssuing(later))

	// earlier than current stop, shorter redemption, not retired → rejected
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: time.Now().Add(day)}, later), "later than")
	short := before.Add(-day)
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop.Add(day), StopRedeemingAt: &short}, later), "shorten")
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", repl, adminapi.PostponeRequest{StopIssuingAt: newStop}, later), "not retired")
}

func (s *AdminDBSuite) TestUpdateRules() {
	id := s.create(adminapi.CreateIssuerRequest{Name: "u", Version: 2, ExpiresAt: ptrTime(time.Now().Add(10 * day))})
	mt := 99
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{MaxTokens: &mt}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().Add(5 * day))}), "extend")
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().Add(20 * day))}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{}), "nothing to update")

	noExp := s.create(v1("noexp")) // Review Focus 2
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", noExp, adminapi.UpdateIssuerRequest{ExpiresAt: ptrTime(time.Now().AddDate(5, 0, 0))}), "no expiry")

	got, _ := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.Equal(99, got.MaxTokens)
}

func (s *AdminDBSuite) TestSignPathSeesRetirement() {
	old, repl := s.create(v1("sgn")), s.create(v1("new-for-sgn"))
	iss, appErr := s.srv.GetLatestIssuer("sgn", v1Cohort)
	s.Require().Nil(appErr)
	s.True(iss.IsIssuing(time.Now()))

	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().Add(93*day)))
	iss, appErr = s.srv.GetLatestIssuer("sgn", v1Cohort)
	s.Require().Nil(appErr, "lookup still works: bulk redeem uses it")
	s.False(iss.IsIssuing(time.Now().Add(time.Second)))

	k, err := s.srv.GetLatestIssuerKafka("sgn", v1Cohort)
	s.Require().NoError(err)
	s.False(k.IsIssuing(time.Now().Add(time.Second)))
}

func (s *AdminDBSuite) TestRotationCronsSkipRetired() {
	old := s.create(v3("cron3", time.Now().AddDate(2, 0, 0)))
	repl := s.create(v1("cronr"))
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().AddDate(0, 7, 0)))
	// force the cron's "needs keys" condition by removing future windows
	_, err := s.srv.db.Exec(`DELETE FROM v3_issuer_keys WHERE issuer_id = $1`, old)
	s.Require().NoError(err)
	_, err = s.srv.db.Exec(`INSERT INTO v3_issuer_keys (issuer_id, signing_key, public_key, cohort, start_at, end_at)
        VALUES ($1, 'x', 'y', 1, now() - interval '2 days', now() - interval '1 day')`, old)
	s.Require().NoError(err)
	time.Sleep(1100 * time.Millisecond) // stop_issuing_at now in the past
	s.Require().NoError(s.srv.rotateIssuersV3())
	var n int
	s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM v3_issuer_keys WHERE issuer_id = $1`, old).Scan(&n))
	s.Equal(1, n, "retired v3 issuer must not get new keys")
}

// C1: offsets must not be dropped when storing into timestamp columns.
func (s *AdminDBSuite) TestNonUTCTimesStoredAsInstants() {
	west := time.FixedZone("UTC-7", -7*3600)
	cur := time.Now().Add(10 * day).Truncate(time.Second).UTC()
	id := s.create(adminapi.CreateIssuerRequest{Name: "zoned", Version: 2, ExpiresAt: &cur})

	later := cur.Add(time.Hour).In(west) // a later instant, expressed at -07:00
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: &later}))
	got, _ := s.srv.adminGetIssuer(s.ctx, id, time.Now())
	s.True(got.ExpiresAt.Equal(later), "stored %s, want %s", got.ExpiresAt, later.UTC())

	repl := s.create(v1("replz"))
	stop := time.Now().Add(time.Hour).In(west)
	redeem := stop.Add(93 * day)
	old := s.create(v1("oldz"))
	s.Require().NoError(s.retire(old, repl, stop, redeem))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.True(got.ExpiresAt.Equal(redeem.Truncate(time.Second)), "stored %s, want %s", got.ExpiresAt, redeem.UTC())
}

// C2: postponing a v3 issuer must keep redemption past every key window the
// cron can still create before the new stop-issuing time.
func (s *AdminDBSuite) TestPostponeV3CoversFutureWindows() {
	old := s.create(v3("pv3", time.Now().AddDate(3, 0, 0))) // P2M, buffer 2, overlap 1 → 6 months of windows
	repl := s.create(v1("repl-pv"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(old, repl, start, start.AddDate(0, 6, 2)))

	newStop := start.Add(30 * day)
	s.Require().NoError(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop}, time.Now()))
	got, _ := s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.False(got.ExpiresAt.Before(newStop.Truncate(time.Second).AddDate(0, 6, 0)), "expires %s must cover windows to %s", got.ExpiresAt, newStop.AddDate(0, 6, 0))

	short := got.ExpiresAt.Add(time.Hour) // later than current, earlier than the window end a one-day postpone adds
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: newStop.Add(day), StopRedeemingAt: &short}, time.Now()), "key window")
}

// I1: Kafka resolves issuers by prefix, so prefix-related names must not be
// created or paired in a retirement.
func (s *AdminDBSuite) TestPrefixRelatedNamesRejected() {
	s.create(v1("pfx"))
	_, err := s.srv.adminCreateIssuer(s.ctx, "op", v1("pfx-next"))
	s.isRule(err, "prefix")
	_, err = s.srv.adminCreateIssuer(s.ctx, "op", v1("pf"))
	s.isRule(err, "prefix")

	// pairs that already exist (legacy create path) cannot be retired onto each other
	s.Require().NoError(s.srv.createIssuer("legacy", v1Cohort, 0, &time.Time{}))
	s.Require().NoError(s.srv.createIssuer("legacy2", v1Cohort, 0, &time.Time{}))
	var a, b uuid.UUID
	s.Require().NoError(s.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type='legacy'`).Scan(&a))
	s.Require().NoError(s.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type='legacy2'`).Scan(&b))
	start := time.Now().Add(time.Minute)
	s.isRule(s.retire(a, b, start, start.Add(93*day)), "prefix")
}

// Kafka's lookup is `LIKE name || '%'`, so `_` in a name is a wildcard.
func (s *AdminDBSuite) TestPrefixCheckTreatsLikeWildcards() {
	s.create(v1("user_wallet"))
	_, err := s.srv.adminCreateIssuer(s.ctx, "op", v1("userXwallet-v2"))
	s.isRule(err, "prefix")
}

// Changing the expiry of an issuer with a prefix sibling reorders Kafka's
// `ORDER BY expires_at DESC` match, so retire, postpone and extend refuse it
// even when the replacement is unrelated.
func (s *AdminDBSuite) TestExpiryChangeRejectedWithPrefixSibling() {
	s.Require().NoError(s.srv.createIssuer("foo", v1Cohort, 0, &time.Time{}))
	s.Require().NoError(s.srv.createIssuer("foo-legacy", v1Cohort, 0, &time.Time{}))
	var legacy uuid.UUID
	s.Require().NoError(s.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type='foo-legacy'`).Scan(&legacy))
	bar := s.create(v1("bar"))
	start := time.Now().Add(time.Minute)
	s.isRule(s.retire(legacy, bar, start, start.Add(93*day)), "prefix")

	soon := time.Now().Add(day)
	_, err := s.srv.db.Exec(`UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, legacy, soon.UTC())
	s.Require().NoError(err)
	later := soon.Add(30 * day)
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", legacy, adminapi.UpdateIssuerRequest{ExpiresAt: &later}), "prefix")

	// postpone: a sibling that appeared after the retirement (legacy create)
	solo, soloRepl := s.create(v1("solo")), s.create(v1("other"))
	s.Require().NoError(s.retire(solo, soloRepl, start, start.Add(93*day)))
	s.Require().NoError(s.srv.createIssuer("solo-x", v1Cohort, 0, &time.Time{}))
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", solo, adminapi.PostponeRequest{StopIssuingAt: start.Add(30 * day)}, time.Now()), "prefix")
}

// An expired issuer must not come back through an expires_at extension.
func (s *AdminDBSuite) TestUpdateRejectsExpiredIssuer() {
	id := s.create(v1("gone"))
	_, err := s.srv.db.Exec(`UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, time.Now().Add(-day).UTC())
	s.Require().NoError(err)
	next := time.Now().AddDate(1, 0, 0)
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: &next}), "expired")
}
