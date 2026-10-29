//go:build db

package server

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	timeutils "github.com/brave-intl/bat-go/libs/time"
	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
	"github.com/google/uuid"
	"github.com/lib/pq"
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
	id, err := s.srv.adminCreateIssuer(s.ctx, "op-test", req)
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
	s.Empty(list[0].Keys, "list does not embed keys")

	audit, err := s.srv.adminListAudit(s.ctx, id, 10)
	s.Require().NoError(err)
	s.Require().Len(audit, 1)
	s.Equal("create", audit[0].Action)
	s.Equal("op-test", audit[0].Operator)
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
	_, err := s.srv.adminCreateIssuer(s.ctx, "op-test", v1("dup"))
	s.Require().Error(err)
	var rows int
	s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM issuer_admin_audit`).Scan(&rows))
	s.Equal(1, rows, "failed create must not leave an audit row")
}

func (s *AdminDBSuite) TestCreateValidation() {
	for _, req := range []adminapi.CreateIssuerRequest{
		{Name: "", Version: 1},
		{Name: "x", Version: 4},
		{Name: "x", Version: 3, Duration: "", Buffer: 1},
		{Name: "x", Version: 3, Duration: "P1M", Buffer: 0},
		{Name: "x", Version: 1, ExpiresAt: ptr.FromTime(time.Now().Add(-time.Hour))},
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

const day = 24 * time.Hour

func (s *AdminDBSuite) retire(id, repl uuid.UUID, stopIssuing, stopRedeeming time.Time) error {
	return s.srv.adminRetireIssuer(s.ctx, "op-test", id, adminapi.RetireRequest{
		ReplacementIssuerID: repl.String(), StopIssuingAt: stopIssuing, StopRedeemingAt: stopRedeeming,
	}, time.Now())
}

func (s *AdminDBSuite) idOf(name string) (id uuid.UUID) {
	s.Require().NoError(s.srv.db.QueryRow(`SELECT issuer_id FROM v3_issuers WHERE issuer_type = $1`, name).Scan(&id))
	return id
}

// withCaching turns issuer caching on for the rest of the test.
func (s *AdminDBSuite) withCaching(expirationSec int) {
	saved := s.srv.dbConfig.CachingConfig
	s.srv.dbConfig.CachingConfig = CachingConfig{Enabled: true, ExpirationSec: expirationSec}
	s.T().Cleanup(func() { s.srv.dbConfig.CachingConfig = saved })
}

// lockTx begins a transaction that takes a lock with query.
func (s *AdminDBSuite) lockTx(query string, args ...any) *sql.Tx {
	tx, err := s.srv.db.Begin()
	s.Require().NoError(err)
	_, err = tx.Exec(query, args...)
	s.Require().NoError(err)
	return tx
}

// blocked runs fn in the background and checks it is still waiting after
// 300ms, that is, on a lock tx holds. Its result arrives on the channel.
func (s *AdminDBSuite) blocked(tx *sql.Tx, fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		_ = tx.Rollback()
		s.FailNow("did not wait for the lock", "err: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	return done
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

	s.Require().NoError(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now()))
	got, _ = s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Equal(adminapi.StatusActive, got.Status)
	s.Nil(got.ExpiresAt, "cancel restores the no-expiry sentinel")

	audit, _ := s.srv.adminListAudit(s.ctx, old, 10)
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
	shortRepl := s.create(adminapi.CreateIssuerRequest{Name: "short", Version: 1, ExpiresAt: ptr.FromTime(now.Add(30 * day))})
	s.isRule(s.retire(old, shortRepl, start, start.Add(93*day)), "replacement expires")

	// replacement that is itself retiring
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
		ValidFrom: &later, ExpiresAt: ptr.FromTime(time.Now().AddDate(2, 0, 0))})
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

// The chain rule compares a timestamp-without-zone column with now. A
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

// After "retire now", sign requests can still succeed until the change
// reaches the reader replica (allowance maxReplicaLag) and, with caching
// on, until cached copies expire. The overlap is measured from then.
func (s *AdminDBSuite) TestRetireNowCountsPropagationDelay() {
	now := time.Now()
	s.Run("replica lag", func() {
		s.SetupTest()
		old, repl := s.create(v1("lag-old")), s.create(v1("lag-new"))
		s.isRule(s.retire(old, repl, now, adminapi.MinStopRedeeming(now).Add(time.Minute)), "last possible issuance")
		s.Require().NoError(s.retire(old, repl, now, adminapi.MinStopRedeeming(now.Add(maxReplicaLag)).Add(time.Minute)))
	})
	s.Run("replica lag plus cache period", func() {
		s.SetupTest()
		old, repl := s.create(v1("cache-old")), s.create(v1("cache-new"))
		s.withCaching(3600)
		s.isRule(s.retire(old, repl, now, adminapi.MinStopRedeeming(now.Add(time.Hour)).Add(time.Minute)), "last possible issuance")
		s.Require().NoError(s.retire(old, repl, now, adminapi.MinStopRedeeming(now.Add(time.Hour+maxReplicaLag)).Add(time.Minute)))
	})
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

// The sign path loads retirement for every row in one query. A v3 issuer
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

// Postponing a retired v3 issuer must give it keys from the current window
// on, on its window grid, whether its keys all lapsed or were all deleted
// (the cron recovers from neither). valid_from is a year back so a rebuild
// from valid_from would leave every window in the past.
func (s *AdminDBSuite) TestPostponeV3RestoresCurrentKey() {
	for _, tc := range []struct {
		name   string
		lapsed bool
	}{{"lapsed keys", true}, {"no keys", false}} {
		s.Run(tc.name, func() {
			s.SetupTest()
			old := s.create(v3("pk3", time.Now().AddDate(2, 0, 0))) // P2M, buffer 2, overlap 1
			repl := s.create(v1("pkr"))
			s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().AddDate(0, 7, 0)))
			validFrom := time.Now().UTC().AddDate(-1, 0, 0).Truncate(time.Second)
			_, err := s.srv.db.Exec(`UPDATE v3_issuers SET valid_from = $2 WHERE issuer_id = $1`, old, validFrom)
			s.Require().NoError(err)
			_, err = s.srv.db.Exec(`DELETE FROM v3_issuer_keys WHERE issuer_id = $1`, old)
			s.Require().NoError(err)
			gridFrom := validFrom
			if tc.lapsed {
				gridFrom = validFrom.AddDate(0, 2, 0)
				_, err = s.srv.db.Exec(`INSERT INTO v3_issuer_keys (issuer_id, signing_key, public_key, cohort, start_at, end_at)
                    VALUES ($1, 'x', 'y', 1, $2, $3)`, old, validFrom, gridFrom)
				s.Require().NoError(err)
			}
			time.Sleep(1100 * time.Millisecond) // retired: stop_issuing_at has passed

			s.Require().NoError(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: time.Now().Add(30 * day)}, time.Now()))
			var start time.Time
			s.Require().NoError(s.srv.db.QueryRow(`SELECT start_at FROM v3_issuer_keys
                WHERE issuer_id = $1 AND start_at <= now() AND end_at > now()`, old).Scan(&start), "needs a key for the current window")
			// step the grid as the server and cron do (ISO duration, not AddDate)
			p2m, err := timeutils.ParseDuration("P2M")
			s.Require().NoError(err)
			onGrid := false
			for t := gridFrom; !t.After(start); {
				onGrid = onGrid || t.Equal(start)
				next, err := p2m.From(t)
				s.Require().NoError(err)
				t = *next
			}
			s.True(onGrid, "current window %s must sit on the P2M grid from %s", start, gridFrom)
			var future int
			s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM v3_issuer_keys WHERE issuer_id = $1 AND end_at > now()`, old).Scan(&future))
			s.Equal(3, future, "buffer + overlap windows from now on")
		})
	}
}

// A retired issuer's expiry is its stop_redeeming_at, so PATCH may not
// extend it past what the replacement covers.
func (s *AdminDBSuite) TestUpdateRetiredIssuerKeepsReplacementCoverage() {
	a, b, c := s.create(v1("cov-a")), s.create(v1("cov-b")), s.create(v1("cov-c"))
	start := time.Now().Add(time.Minute)
	s.Require().NoError(s.retire(a, b, start, start.Add(93*day)))
	s.Require().NoError(s.retire(b, c, start.Add(95*day), start.Add(200*day)))
	beyond := start.Add(150 * day)
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", a, adminapi.UpdateIssuerRequest{ExpiresAt: &beyond}), "replacement stops issuing")
	within := start.Add(94 * day)
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", a, adminapi.UpdateIssuerRequest{ExpiresAt: &within}))
}

// Postpone locks the replacement too, so it waits for a concurrent change
// to the replacement (here, a held row lock) instead of validating against
// stale state.
func (s *AdminDBSuite) TestPostponeLocksReplacement() {
	a, b := s.create(v1("lk-a")), s.create(v1("lk-b"))
	s.Require().NoError(s.retire(a, b, time.Now(), time.Now().Add(93*day)))
	time.Sleep(1100 * time.Millisecond)

	tx := s.lockTx(`SELECT 1 FROM v3_issuers WHERE issuer_id = $1 FOR UPDATE`, b)
	done := s.blocked(tx, func() error {
		return s.srv.adminPostponeRetirement(s.ctx, "op", a, adminapi.PostponeRequest{StopIssuingAt: time.Now().Add(30 * day)}, time.Now())
	})
	s.Require().NoError(tx.Rollback())
	s.Require().NoError(<-done)
}

// With caching on and a non-positive CACHE_DURATION_SECS, cache entries
// never expire, so retirement changes would never reach other pods.
func (s *AdminDBSuite) TestRetirementChangesNeedExpiringCache() {
	old, repl := s.create(v1("nc-old")), s.create(v1("nc-new"))
	start := time.Now().Add(time.Hour)
	s.Require().NoError(s.retire(old, repl, start, start.Add(93*day)))
	s.withCaching(0)

	other := s.create(v1("nc-other"))
	s.isRule(s.retire(other, repl, start, start.Add(93*day)), "never expire")
	s.isRule(s.srv.adminPostponeRetirement(s.ctx, "op", old, adminapi.PostponeRequest{StopIssuingAt: start.Add(day)}, time.Now()), "never expire")
	s.isRule(s.srv.adminCancelRetirement(s.ctx, "op", old, time.Now()), "never expire")
}

// Legacy create routes must not make a prefix sibling of a retired issuer
// (Kafka would sign the retired one's requests with it), but still allow
// siblings of issuers that were never retired.
func (s *AdminDBSuite) TestLegacyCreateRefusesSiblingOfRetired() {
	ret := s.create(v1("lx"))
	s.Require().NoError(s.retire(ret, s.create(v1("other-repl")), time.Now().Add(time.Hour), time.Now().Add(94*day)))
	s.ErrorIs(s.srv.createIssuer("lx-next", v1Cohort, 0, &time.Time{}), errRetiredPrefixSibling)
	s.ErrorIs(s.srv.createIssuerV2("lx-next", v1Cohort, 0, &time.Time{}), errRetiredPrefixSibling)

	s.create(v1("free"))
	s.NoError(s.srv.createIssuer("free-next", v1Cohort, 0, &time.Time{}), "legacy naming is unchanged for issuers never retired")
}

// The runbook's break-glass SQL must run and apply the postpone rules.
func (s *AdminDBSuite) TestBreakGlassSQL() {
	doc, err := os.ReadFile("/src/docs/issuer-admin-rollout.md")
	s.Require().NoError(err)
	block := regexp.MustCompile("(?s)Break-glass SQL.*?```sql\n(.*?)```").FindSubmatch(doc)
	s.Require().NotNil(block, "break-glass SQL block not found")

	old := s.create(v3("bg3", time.Now().AddDate(2, 0, 0))) // P2M, buffer 2, overlap 1
	repl := s.create(v1("bg-repl"))
	// just past the v3 minimum, so a 30-day postpone must extend redemption
	s.Require().NoError(s.retire(old, repl, time.Now(), time.Now().AddDate(0, 6, 2)))
	sqlText := strings.NewReplacer("<issuer uuid>", old.String(), "<your operator id>", "op-test", "<why>", "test").Replace(string(block[1]))
	_, err = s.srv.db.Exec(sqlText)
	s.Require().NoError(err)

	got, err := s.srv.adminGetIssuer(s.ctx, old, time.Now())
	s.Require().NoError(err)
	s.Equal(adminapi.StatusRetiring, got.Status, "issuing again")
	newStop := *got.StopIssuingAt
	s.False(got.ExpiresAt.Before(adminapi.MinStopRedeeming(newStop).Add(-time.Minute)), "3 months after the new stop")
	s.False(got.ExpiresAt.Before(newStop.AddDate(0, 6, 0).Add(-time.Minute)), "covers v3 windows: 3 x P2M")
}

// Admin creates are serialized, so a create that waits on a concurrent one
// sees the sibling it committed and refuses.
func (s *AdminDBSuite) TestCreateWaitsForConcurrentCreate() {
	tx := s.lockTx(`SELECT pg_advisory_xact_lock($1)`, prefixLock)
	done := s.blocked(tx, func() error {
		_, err := s.srv.adminCreateIssuer(s.ctx, "op", v1("race"))
		return err
	})
	// the concurrent create commits a sibling (inserted under its lock)
	_, err := tx.Exec(`INSERT INTO v3_issuers (issuer_type, version) VALUES ('race-next', 1)`)
	s.Require().NoError(err)
	s.Require().NoError(tx.Commit())
	s.isRule(<-done, "prefix")
}

// Retire takes the prefix lock too, so a concurrent legacy create of a
// sibling cannot pass its retired-only check at the same time.
func (s *AdminDBSuite) TestRetireWaitsForConcurrentCreate() {
	old, repl := s.create(v1("rw")), s.create(v1("other-rw"))
	tx := s.lockTx(`SELECT pg_advisory_xact_lock($1)`, prefixLock)
	start := time.Now().Add(time.Hour)
	done := s.blocked(tx, func() error { return s.retire(old, repl, start, start.Add(93*day)) })
	_, err := tx.Exec(`INSERT INTO v3_issuers (issuer_type, version) VALUES ('rw-next', 1)`)
	s.Require().NoError(err)
	s.Require().NoError(tx.Commit())
	s.isRule(<-done, "prefix")
}

// The v1/v2 rotation cron must not add keys to a retired issuer.
func (s *AdminDBSuite) TestRotateV1SkipsRetired() {
	ret, ctl := s.create(v1("rot-ret")), s.create(v1("rot-ctl"))
	s.Require().NoError(s.retire(ret, s.create(v1("rot-repl")), time.Now(), time.Now().Add(93*day)))
	// put both inside the cron's "expires soon, not rotated lately" window
	_, err := s.srv.db.Exec(`UPDATE v3_issuers SET expires_at = now() + interval '1 day',
        last_rotated_at = now() - interval '30 days' WHERE issuer_id = ANY($1)`, pq.Array([]uuid.UUID{ret, ctl}))
	s.Require().NoError(err)
	time.Sleep(1100 * time.Millisecond) // stop_issuing_at now in the past

	keys := func(id uuid.UUID) (n int) {
		s.Require().NoError(s.srv.db.QueryRow(`SELECT count(*) FROM v3_issuer_keys WHERE issuer_id = $1`, id).Scan(&n))
		return n
	}
	retBefore, ctlBefore := keys(ret), keys(ctl)
	s.Require().NoError(s.srv.rotateIssuers())
	s.Equal(retBefore, keys(ret), "retired issuer must not rotate")
	s.Greater(keys(ctl), ctlBefore, "control issuer rotates")
}

// The legacy create path used to swallow database errors on rollback.
func (s *AdminDBSuite) TestLegacyCreateReturnsDBError() {
	s.Require().NoError(s.srv.createIssuer("dup", v1Cohort, 0, &time.Time{}))
	s.Error(s.srv.createIssuer("dup", v1Cohort, 0, &time.Time{}), "unique violation must surface")
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
	id := s.create(adminapi.CreateIssuerRequest{Name: "u", Version: 2, ExpiresAt: ptr.FromTime(time.Now().Add(10 * day))})
	mt := 99
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{MaxTokens: &mt}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptr.FromTime(time.Now().Add(5 * day))}), "extend")
	s.Require().NoError(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{ExpiresAt: ptr.FromTime(time.Now().Add(20 * day))}))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", id, adminapi.UpdateIssuerRequest{}), "nothing to update")

	noExp := s.create(v1("noexp"))
	s.isRule(s.srv.adminUpdateIssuer(s.ctx, "op", noExp, adminapi.UpdateIssuerRequest{ExpiresAt: ptr.FromTime(time.Now().AddDate(5, 0, 0))}), "no expiry")

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

// Offsets must not be dropped when storing into timestamp columns.
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

// Postponing a v3 issuer must keep redemption past every key window the
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

// Kafka resolves issuers by prefix, so prefix-related names must not be
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
	start := time.Now().Add(time.Minute)
	s.isRule(s.retire(s.idOf("legacy"), s.idOf("legacy2"), start, start.Add(93*day)), "prefix")
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
	legacy := s.idOf("foo-legacy")
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
	// legacy create now refuses this name, so insert it directly
	_, err = s.srv.db.Exec(`INSERT INTO v3_issuers (issuer_type, version) VALUES ('solo-x', 1)`)
	s.Require().NoError(err)
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
