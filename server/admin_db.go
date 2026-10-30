package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	timeutils "github.com/brave-intl/bat-go/libs/time"
	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var errAdminNotFound = errors.New("issuer not found")

// adminRuleError is a request that violates an admin rule (HTTP 422).
type adminRuleError struct{ msg string }

func (e *adminRuleError) Error() string { return e.msg }

func ruleErr(format string, args ...any) error {
	return &adminRuleError{msg: fmt.Sprintf(format, args...)}
}

// utcTime normalizes a request time. v3_issuers time columns are
// `timestamp` without time zone and Postgres drops any offset lib/pq sends,
// so a non-UTC value would be stored at the wrong instant.
func utcTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// prefixLock is the advisory lock key held while checking for prefix
// siblings. Every create, retire, postpone and expiry change takes the lock,
// so two concurrent requests (say, a create of X-next and a retire of X)
// cannot both pass the check.
const prefixLock = 0x63627069737375 // "cbpissu"

// txPrefixSibling returns the name of another issuer that Kafka's sign
// lookup can confuse with name, or "" if there is none. With retiredOnly,
// txPrefixSibling considers only issuers that have a retirement row.
// GetLatestIssuerKafka matches `issuer_type LIKE name || '%'` and picks the
// match with the later expiry. When two names match each other this way, a
// sign request for one issuer can be signed by the other issuer. Changing
// either issuer's expires_at can also change which issuer signs. The check
// uses LIKE, not a plain prefix compare, because `_` and `%` in a name are
// LIKE wildcards.
func txPrefixSibling(ctx context.Context, tx *sql.Tx, name string, retiredOnly bool) (string, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, prefixLock); err != nil {
		return "", err
	}
	var sibling string
	err := tx.QueryRowContext(ctx, `
        SELECT i.issuer_type FROM v3_issuers i
        WHERE i.issuer_type <> $1
          AND (i.issuer_type LIKE $1 || '%' OR $1 LIKE i.issuer_type || '%')
          AND (NOT $2 OR EXISTS (SELECT 1 FROM issuer_retirements r WHERE r.issuer_id = i.issuer_id))
        LIMIT 1`, name, retiredOnly).Scan(&sibling)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return sibling, err
}

// txRejectPrefixSibling refuses an expires_at change on an issuer that has a
// prefix sibling, since the change can reroute the sibling's sign requests.
func txRejectPrefixSibling(ctx context.Context, tx *sql.Tx, name string) error {
	sibling, err := txPrefixSibling(ctx, tx, name, false)
	if err != nil || sibling == "" {
		return err
	}
	return ruleErr("issuer %q and existing issuer %q match each other in Kafka's prefix lookup, so changing this expiry could reroute sign requests between them", name, sibling)
}

// nullableTime maps NULL and the 0001-01-01 "no expiry" sentinel to nil.
func nullableTime(t pq.NullTime) *time.Time {
	if !t.Valid || t.Time.Year() <= 1 {
		return nil
	}
	v := t.Time
	return &v
}

const adminIssuerSelect = `
SELECT i.issuer_id, i.issuer_type, i.version, i.issuer_cohort, i.max_tokens,
       i.buffer, i.overlap, i.duration, i.created_at, i.valid_from, i.expires_at,
       r.stop_issuing_at, r.replacement_issuer_id,
       (SELECT max(end_at) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id)
FROM v3_issuers i
LEFT JOIN issuer_retirements r ON r.issuer_id = i.issuer_id`

type rowScanner interface{ Scan(dest ...any) error }

func scanAdminIssuer(row rowScanner, now time.Time) (adminapi.Issuer, error) {
	var (
		out                         adminapi.Issuer
		duration, replacement       sql.NullString
		created, validFrom, expires pq.NullTime
		stopIssuing, latestEnd      pq.NullTime
	)
	err := row.Scan(&out.ID, &out.Name, &out.Version, &out.Cohort, &out.MaxTokens,
		&out.Buffer, &out.Overlap, &duration, &created, &validFrom, &expires,
		&stopIssuing, &replacement, &latestEnd)
	if err != nil {
		return out, err
	}
	if duration.Valid && duration.String != "" {
		out.Duration = &duration.String
	}
	if replacement.Valid {
		out.ReplacementID = &replacement.String
	}
	out.CreatedAt = nullableTime(created)
	out.ValidFrom = nullableTime(validFrom)
	out.ExpiresAt = nullableTime(expires)
	out.StopIssuingAt = nullableTime(stopIssuing)
	out.LatestKeyEnd = nullableTime(latestEnd)
	out.Status = adminapi.DeriveStatus(now, out.ExpiresAt, out.StopIssuingAt)
	return out, nil
}

func (c *Server) adminListIssuers(ctx context.Context, now time.Time) ([]adminapi.Issuer, error) {
	rows, err := c.db.QueryContext(ctx, adminIssuerSelect+` ORDER BY i.issuer_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminapi.Issuer{}
	for rows.Next() {
		iss, err := scanAdminIssuer(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, iss)
	}
	return out, rows.Err()
}

func (c *Server) adminGetIssuer(ctx context.Context, id uuid.UUID, now time.Time) (*adminapi.Issuer, error) {
	iss, err := scanAdminIssuer(c.db.QueryRowContext(ctx, adminIssuerSelect+` WHERE i.issuer_id = $1`, id), now)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errAdminNotFound
	}
	if err != nil {
		return nil, err
	}

	// Private signing keys are not selected, so they never leave the server.
	rows, err := c.db.QueryContext(ctx, `
        SELECT key_id, public_key, cohort, start_at, end_at
        FROM v3_issuer_keys WHERE issuer_id = $1
        ORDER BY end_at ASC NULLS FIRST, start_at ASC, created_at ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k adminapi.Key
		var pub sql.NullString
		var start, end pq.NullTime
		if err := rows.Scan(&k.ID, &pub, &k.Cohort, &start, &end); err != nil {
			return nil, err
		}
		k.PublicKey = pub.String
		k.StartAt, k.EndAt = nullableTime(start), nullableTime(end)
		iss.Keys = append(iss.Keys, k)
	}
	return &iss, rows.Err()
}

func txInsertAudit(ctx context.Context, tx *sql.Tx, operator, action string, issuerID *uuid.UUID, request any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO issuer_admin_audit (operator, action, issuer_id, request) VALUES ($1, $2, $3, $4)`,
		operator, action, issuerID, body)
	return err
}

func (c *Server) adminListAudit(ctx context.Context, issuerID uuid.UUID, limit int) ([]adminapi.AuditEntry, error) {
	rows, err := c.db.QueryContext(ctx, `
        SELECT id, created_at, operator, action, issuer_id, request
        FROM issuer_admin_audit
        WHERE issuer_id = $1
        ORDER BY created_at DESC, id DESC LIMIT $2`, issuerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminapi.AuditEntry{}
	for rows.Next() {
		var e adminapi.AuditEntry
		var iid sql.NullString
		var req []byte
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Operator, &e.Action, &iid, &req); err != nil {
			return nil, err
		}
		if iid.Valid {
			e.IssuerID = &iid.String
		}
		e.Request = req
		out = append(out, e)
	}
	return out, rows.Err()
}

func validateCreate(req adminapi.CreateIssuerRequest, now time.Time) error {
	if strings.TrimSpace(req.Name) == "" {
		return ruleErr("name is required")
	}
	if req.Version < 1 || req.Version > 3 {
		return ruleErr("version must be 1, 2 or 3")
	}
	if req.MaxTokens < 0 {
		return ruleErr("max_tokens must be >= 0")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		return ruleErr("expires_at must be in the future")
	}
	if req.Version == 3 {
		if req.Duration == "" {
			return ruleErr("duration is required for v3")
		}
		if _, err := timeutils.ParseDuration(req.Duration); err != nil {
			return ruleErr("duration %q is not an ISO 8601 duration", req.Duration)
		}
		if req.Buffer < 1 || req.Overlap < 0 {
			return ruleErr("v3 needs buffer >= 1 and overlap >= 0")
		}
		if req.ExpiresAt == nil {
			return ruleErr("v3 issuers need expires_at (the rotation cron skips v3 issuers without one)")
		}
	} else if req.Duration != "" || req.Buffer != 0 || req.Overlap != 0 || req.ValidFrom != nil {
		return ruleErr("duration, buffer, overlap and valid_from are v3-only")
	}
	return nil
}

func (c *Server) adminCreateIssuer(ctx context.Context, operator string, req adminapi.CreateIssuerRequest) (uuid.UUID, error) {
	req.ExpiresAt, req.ValidFrom = utcTime(req.ExpiresAt), utcTime(req.ValidFrom)
	if err := validateCreate(req, time.Now()); err != nil {
		return uuid.Nil, err
	}
	cohort := req.Cohort
	if cohort == 0 {
		cohort = v1Cohort
	}
	iss := model.Issuer{
		IssuerType:   req.Name,
		IssuerCohort: cohort,
		MaxTokens:    req.MaxTokens,
		Version:      req.Version,
		ExpiresAt:    pq.NullTime{Valid: true}, // 0001-01-01, the "no expiry" value legacy creates store
	}
	if req.ExpiresAt != nil {
		iss.ExpiresAt.Time = *req.ExpiresAt
	}
	if req.Version == 3 {
		iss.Buffer, iss.Overlap, iss.ValidFrom = req.Buffer, req.Overlap, req.ValidFrom
		if iss.ValidFrom == nil {
			// The legacy create path leaves this nil, so the first key
			// windows land in year 0001 until the rotation cron catches up.
			// Admin-created issuers get real windows immediately.
			now := time.Now().UTC()
			iss.ValidFrom = &now
		}
		d := req.Duration
		iss.Duration = &d
	}

	var id uuid.UUID
	err := c.withTx(ctx, func(tx *sql.Tx) error {
		clash, err := txPrefixSibling(ctx, tx, req.Name, false)
		if err != nil {
			return err
		}
		if clash != "" {
			return ruleErr("name %q and existing issuer %q match each other in Kafka's prefix lookup (`_` and `%%` are wildcards there), so pick a name that does not", req.Name, clash)
		}
		if id, err = txCreateV3Issuer(tx, c.Logger, iss); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "create", &id, req)
	})
	return id, err
}

type lockedIssuer struct {
	id                       uuid.UUID
	name                     string
	version, buffer, overlap int
	cohort                   int16
	duration                 sql.NullString
	validFrom, expiresAt     pq.NullTime
	stopIssuingAt, maxKeyEnd *time.Time
	replacement              uuid.UUID // uuid.Nil when not retired
}

func (l lockedIssuer) status(now time.Time) adminapi.Status {
	return adminapi.DeriveStatus(now, nullableTime(l.expiresAt), l.stopIssuingAt)
}

// txLockIssuers locks the given issuer rows in id order (deadlock-safe) and
// returns them keyed by id, with their retirement and latest key end. A
// missing ids[0] is errAdminNotFound. Any other missing id is a rule error,
// since that id came from the request body and not the URL.
func txLockIssuers(ctx context.Context, tx *sql.Tx, ids ...uuid.UUID) (map[uuid.UUID]*lockedIssuer, error) {
	// Lock first, then read in a second statement. A statement that waits on
	// a row lock re-reads only the locked row, so joined retirement columns
	// would be stale. Every writer of issuer_retirements holds the issuer's
	// row lock, so the second statement sees their committed result.
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM v3_issuers WHERE issuer_id = ANY($1) ORDER BY issuer_id FOR UPDATE`, pq.Array(ids)); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
        SELECT i.issuer_id, i.issuer_type, i.version, i.buffer, i.overlap, i.issuer_cohort,
               i.duration, i.valid_from, i.expires_at, r.stop_issuing_at, r.replacement_issuer_id,
               (SELECT max(end_at) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id)
        FROM v3_issuers i LEFT JOIN issuer_retirements r ON r.issuer_id = i.issuer_id
        WHERE i.issuer_id = ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]*lockedIssuer{}
	for rows.Next() {
		l := &lockedIssuer{}
		var stop, maxEnd pq.NullTime
		var repl uuid.NullUUID
		if err := rows.Scan(&l.id, &l.name, &l.version, &l.buffer, &l.overlap, &l.cohort,
			&l.duration, &l.validFrom, &l.expiresAt, &stop, &repl, &maxEnd); err != nil {
			return nil, err
		}
		l.stopIssuingAt, l.maxKeyEnd, l.replacement = nullableTime(stop), nullableTime(maxEnd), repl.UUID
		out[l.id] = l
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, id := range ids {
		if out[id] != nil {
			continue
		}
		if i == 0 {
			return nil, errAdminNotFound
		}
		return nil, ruleErr("issuer %s does not exist", id)
	}
	return out, nil
}

func (c *Server) adminUpdateIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.UpdateIssuerRequest) error {
	if req.MaxTokens == nil && req.ExpiresAt == nil {
		return ruleErr("nothing to update: only max_tokens and expires_at are mutable")
	}
	req.ExpiresAt = utcTime(req.ExpiresAt)
	if req.MaxTokens != nil && *req.MaxTokens < 0 {
		return ruleErr("max_tokens must be >= 0")
	}
	return c.withTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockWithReplacement(ctx, tx, id)
		if err != nil {
			return err
		}
		l := locked[id]
		if l.status(time.Now()) == adminapi.StatusExpired {
			return ruleErr("issuer has expired; create a new issuer instead")
		}
		if req.ExpiresAt != nil {
			if err := txRejectPrefixSibling(ctx, tx, l.name); err != nil {
				return err
			}
			cur := nullableTime(l.expiresAt)
			if cur == nil {
				return ruleErr("issuer has no expiry; setting one would shorten it")
			}
			if !req.ExpiresAt.After(*cur) {
				return ruleErr("expires_at can only extend (current %s)", cur.UTC().Format(time.RFC3339))
			}
			// A retired issuer's expires_at is its stop_redeeming_at. So the
			// replacement must not expire or stop issuing before the new
			// expires_at. Postpone applies the same check.
			if l.replacement != uuid.Nil {
				if err := replacementCovers(locked[l.replacement], *req.ExpiresAt); err != nil {
					return err
				}
			}
			if err := txSetExpiry(ctx, tx, id, *req.ExpiresAt); err != nil {
				return err
			}
		}
		if req.MaxTokens != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET max_tokens = $2 WHERE issuer_id = $1`, id, *req.MaxTokens); err != nil {
				return err
			}
		}
		return txInsertAudit(ctx, tx, operator, "update", &id, req)
	})
}

// maxReplicaLag bounds how long a committed retirement can take to reach
// the reader replica that the sign path reads (fetchStopIssuingAt).
const maxReplicaLag = 5 * time.Minute

// requireExpiringCache refuses retirement changes when issuer cache entries
// never expire, since other pods would never see the change.
// CACHE_DURATION_SECS <= 0 makes SimpleCache keep entries forever.
func (c *Server) requireExpiringCache() error {
	if cc := c.dbConfig.CachingConfig; cc.Enabled && cc.ExpirationSec <= 0 {
		return ruleErr("issuer caching is on with CACHE_DURATION_SECS=%d, so cache entries never expire and other pods would never see this change; set a positive value first", cc.ExpirationSec)
	}
	return nil
}

// txLockWithReplacement locks the issuer and, if the issuer is retired, its
// replacement, in one id-ordered statement like retire does. A deadline
// change on the issuer and a concurrent retire of the replacement then run
// one after the other, and each one validates against the committed result
// of the other.
func txLockWithReplacement(ctx context.Context, tx *sql.Tx, id uuid.UUID) (map[uuid.UUID]*lockedIssuer, error) {
	var replID uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT replacement_issuer_id FROM issuer_retirements WHERE issuer_id = $1`, id).Scan(&replID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	ids := []uuid.UUID{id}
	if replID != uuid.Nil {
		ids = append(ids, replID)
	}
	locked, err := txLockIssuers(ctx, tx, ids...)
	if err != nil {
		return nil, err
	}
	// A cancel or re-retire may have committed before the lock was taken.
	if locked[id].replacement != replID {
		return nil, ruleErr("the retirement changed while this request ran; retry")
	}
	return locked, nil
}

// replacementCovers refuses redeem as a stop_redeeming_at when the
// replacement expires or stops issuing before redeem.
func replacementCovers(repl *lockedIssuer, redeem time.Time) error {
	if e := nullableTime(repl.expiresAt); e != nil && e.Before(redeem) {
		return ruleErr("replacement expires at %s, before the new stop_redeeming_at; extend it first", e.UTC().Format(time.RFC3339))
	}
	if s := repl.stopIssuingAt; s != nil && s.Before(redeem) {
		return ruleErr("replacement stops issuing at %s, before the new stop_redeeming_at; postpone it first", s.UTC().Format(time.RFC3339))
	}
	return nil
}

func txSetExpiry(ctx context.Context, tx *sql.Tx, id uuid.UUID, expiresAt any) error {
	_, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, expiresAt)
	return err
}

// txCatchUpV3Keys creates keys for a v3 issuer from the current window
// onward when the issuer has no key valid at now. The rotation cron cannot
// do this. The cron skips an issuer with no keys. For an issuer with only
// lapsed keys, the cron rebuilds from valid_from, which can leave every
// window in the past. The new windows start at the last key end (or
// valid_from) and step by the issuer's duration.
func (c *Server) txCatchUpV3Keys(ctx context.Context, tx *sql.Tx, l *lockedIssuer, now time.Time) error {
	now = now.UTC()
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_issuer_keys
        WHERE issuer_id = $1 AND start_at <= $2 AND end_at > $2`, l.id, now).Scan(&current); err != nil {
		return err
	}
	if current > 0 {
		return nil
	}
	duration := l.duration
	d, err := timeutils.ParseDuration(duration.String)
	if err != nil {
		return fmt.Errorf("issuer duration %q: %w", duration.String, err)
	}
	start := l.validFrom.Time
	if l.maxKeyEnd != nil {
		start = *l.maxKeyEnd
	}
	for {
		end, err := d.From(start)
		if err != nil {
			return err
		}
		if !end.After(start) {
			return fmt.Errorf("issuer duration %q does not advance", duration.String)
		}
		if end.After(now) {
			break
		}
		start = *end
	}
	return txPopulateIssuerKeys(c.Logger, tx, model.Issuer{
		ID: &l.id, Version: 3, IssuerCohort: l.cohort, Buffer: l.buffer, Overlap: l.overlap,
		Duration: &duration.String, ValidFrom: &start,
	})
}

// windowsEnd is the earliest stop_redeeming_at that covers every v3 key
// window, both the existing ones and those the cron can still create before
// stopIssuing. windowsEnd returns the zero time for v1 and v2.
func windowsEnd(l *lockedIssuer, stopIssuing time.Time) (time.Time, error) {
	if l.version < 3 {
		return time.Time{}, nil
	}
	end, err := adminapi.WindowsEnd(l.duration.String, l.buffer+l.overlap, stopIssuing)
	if err != nil {
		return time.Time{}, err
	}
	if l.maxKeyEnd != nil && l.maxKeyEnd.After(end) {
		end = *l.maxKeyEnd
	}
	return end, nil
}

func (c *Server) adminRetireIssuer(ctx context.Context, operator string, id uuid.UUID, req adminapi.RetireRequest, now time.Time) error {
	replID, err := uuid.Parse(req.ReplacementIssuerID)
	if err != nil {
		return ruleErr("replacement_issuer_id is not a uuid")
	}
	if replID == id {
		return ruleErr("replacement must be a different issuer")
	}
	// Whole seconds: Postgres rounds to microseconds, which would make
	// equality comparisons between stored and requested times flaky.
	now = now.Truncate(time.Second)
	stopIssuing, stopRedeeming := req.StopIssuingAt.UTC().Truncate(time.Second), req.StopRedeemingAt.UTC().Truncate(time.Second)
	if stopIssuing.Before(now) && now.Sub(stopIssuing) <= time.Minute {
		stopIssuing = now // tolerate small client clock skew
	}
	if stopIssuing.Before(now) {
		return ruleErr("stop_issuing_at must not be in the past")
	}
	if err := c.requireExpiringCache(); err != nil {
		return err
	}
	// The sign path reads retirement from the reader replica, and pods that
	// cached the issuer before this change keep signing until the cache
	// entry expires. So signing can continue until now + replica lag + cache
	// period. When that time is later than stop_issuing_at, the redemption
	// minimum is measured from that time instead.
	propagated := now.Add(maxReplicaLag)
	if cc := c.dbConfig.CachingConfig; cc.Enabled {
		// @TODO: this assumes every pod (HTTP and Kafka) runs this pod's
		// CACHE_DURATION_SECS. Pass the fleet maximum here if they differ.
		propagated = propagated.Add(time.Duration(cc.ExpirationSec) * time.Second)
	}
	lastIssue := stopIssuing
	if propagated.After(lastIssue) {
		lastIssue = propagated
	}
	if min := adminapi.MinStopRedeeming(lastIssue); stopRedeeming.Before(min) {
		return ruleErr("stop_redeeming_at must be at or after %s: 3 months and at least 90 days after the last possible issuance", min.Format(time.RFC3339))
	}

	return c.withTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id, replID)
		if err != nil {
			return err
		}
		target, repl := locked[id], locked[replID]

		if st := target.status(now); st != adminapi.StatusActive {
			return ruleErr("issuer is already %s", st)
		}
		if st := repl.status(now); st != adminapi.StatusActive {
			return ruleErr("replacement must be active (it is %s)", st)
		}
		// txRejectPrefixSibling checks every other issuer, including the
		// replacement.
		if err := txRejectPrefixSibling(ctx, tx, target.name); err != nil {
			return err
		}
		if err := replacementCovers(repl, stopRedeeming); err != nil {
			return err
		}
		if vf := nullableTime(repl.validFrom); vf != nil && vf.Truncate(time.Second).After(stopIssuing) {
			return ruleErr("replacement valid_from %s is after stop_issuing_at", vf.UTC().Format(time.RFC3339))
		}

		// If the target is the replacement for another retired issuer that
		// still redeems, the target must keep issuing until that other
		// issuer stops redeeming.
		var promised pq.NullTime
		err = tx.QueryRowContext(ctx, `
            SELECT max(i.expires_at) FROM issuer_retirements r
            JOIN v3_issuers i ON i.issuer_id = r.issuer_id
            WHERE r.replacement_issuer_id = $1 AND i.expires_at > $2`, id, now.UTC()).Scan(&promised)
		if err != nil {
			return err
		}
		if p := nullableTime(promised); p != nil && stopIssuing.Before(*p) {
			return ruleErr("stop_issuing_at is before %s, the overlap promised to the issuer this one replaces", p.UTC().Format(time.RFC3339))
		}

		need, err := windowsEnd(target, stopIssuing)
		if err != nil {
			return err
		}
		if stopRedeeming.Before(need) {
			return ruleErr("stop_redeeming_at must be at or after %s, the last key window that can be issued", need.UTC().Format(time.RFC3339))
		}

		if _, err := tx.ExecContext(ctx, `
            INSERT INTO issuer_retirements
                (issuer_id, replacement_issuer_id, stop_issuing_at, expires_at_before_retire)
            VALUES ($1, $2, $3, $4)`,
			id, replID, stopIssuing, target.expiresAt); err != nil {
			return err
		}
		if err := txSetExpiry(ctx, tx, id, stopRedeeming); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "retire", &id, adminapi.RetireRequest{
			ReplacementIssuerID: req.ReplacementIssuerID, StopIssuingAt: stopIssuing, StopRedeemingAt: stopRedeeming,
		})
	})
}

// adminPostponeRetirement moves stop_issuing_at later on a retiring or
// retired issuer, for when clients still use the issuer. stop_redeeming_at
// never moves earlier. The request is refused if the replacement would
// expire or stop issuing before the issuer stops redeeming.
func (c *Server) adminPostponeRetirement(ctx context.Context, operator string, id uuid.UUID, req adminapi.PostponeRequest, now time.Time) error {
	if err := c.requireExpiringCache(); err != nil {
		return err
	}
	return c.withTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockWithReplacement(ctx, tx, id)
		if err != nil {
			return err
		}
		l := locked[id]
		st := l.status(now)
		if l.stopIssuingAt == nil {
			return ruleErr("issuer is not retired")
		}
		if st == adminapi.StatusExpired {
			return ruleErr("issuer has expired; create a new issuer instead")
		}
		if err := txRejectPrefixSibling(ctx, tx, l.name); err != nil {
			return err
		}
		req.StopIssuingAt = req.StopIssuingAt.UTC().Truncate(time.Second)
		if req.StopRedeemingAt != nil {
			t := req.StopRedeemingAt.UTC().Truncate(time.Second)
			req.StopRedeemingAt = &t
		}
		if !req.StopIssuingAt.After(*l.stopIssuingAt) || req.StopIssuingAt.Before(now.Truncate(time.Second)) {
			return ruleErr("stop_issuing_at must be later than the current %s and not in the past", l.stopIssuingAt.UTC().Format(time.RFC3339))
		}
		cur := nullableTime(l.expiresAt)
		redeem := adminapi.MinStopRedeeming(req.StopIssuingAt)
		if cur != nil && cur.After(redeem) {
			redeem = *cur
		}
		if req.StopRedeemingAt != nil {
			if cur != nil && req.StopRedeemingAt.Before(*cur) {
				return ruleErr("stop_redeeming_at would shorten redemption (current %s)", cur.UTC().Format(time.RFC3339))
			}
			if min := adminapi.MinStopRedeeming(req.StopIssuingAt); req.StopRedeemingAt.Before(min) {
				return ruleErr("stop_redeeming_at must be at or after %s: 3 months and at least 90 days after stop_issuing_at", min.Format(time.RFC3339))
			}
			redeem = *req.StopRedeemingAt
		}
		// v3 tokens are signed for future windows, and the cron keeps adding
		// keys until the new stop_issuing_at. So stop_redeeming_at must reach
		// the end of the last window the cron can create.
		need, err := windowsEnd(l, req.StopIssuingAt)
		if err != nil {
			return err
		}
		if req.StopRedeemingAt != nil && req.StopRedeemingAt.Before(need) {
			return ruleErr("stop_redeeming_at must be at or after %s, the last key window that can be issued", need.UTC().Format(time.RFC3339))
		}
		if redeem.Before(need) {
			redeem = need
		}

		// The replacement must not expire or stop issuing before the new
		// stop_redeeming_at.
		if err := replacementCovers(locked[l.replacement], redeem); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issuer_retirements SET stop_issuing_at = $2 WHERE issuer_id = $1`, id, req.StopIssuingAt); err != nil {
			return err
		}
		if err := txSetExpiry(ctx, tx, id, redeem); err != nil {
			return err
		}
		// The rotation cron skipped this issuer while the issuer was retired.
		if l.version >= 3 {
			if err := c.txCatchUpV3Keys(ctx, tx, l, now); err != nil {
				return err
			}
		}
		return txInsertAudit(ctx, tx, operator, "postpone", &id, req)
	})
}

func (c *Server) adminCancelRetirement(ctx context.Context, operator string, id uuid.UUID, now time.Time) error {
	if err := c.requireExpiringCache(); err != nil {
		return err
	}
	return c.withTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
		if err != nil {
			return err
		}
		if st := locked[id].status(now); st != adminapi.StatusRetiring {
			return ruleErr("retirement can be cancelled only while retiring (issuer is %s)", st)
		}
		var before pq.NullTime
		if err := tx.QueryRowContext(ctx,
			`DELETE FROM issuer_retirements WHERE issuer_id = $1 RETURNING expires_at_before_retire`, id).Scan(&before); err != nil {
			return err
		}
		// Restore the later of expires_at_before_retire and the current
		// expires_at, so cancel never shortens redemption. A pre-retire "no
		// expiry" value always wins.
		restore := before
		if b, cur := nullableTime(before), nullableTime(locked[id].expiresAt); b != nil && cur != nil && cur.After(*b) {
			restore = locked[id].expiresAt
		}
		if err := txSetExpiry(ctx, tx, id, restore); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "cancel_retire", &id, map[string]string{"issuer_id": id.String()})
	})
}
