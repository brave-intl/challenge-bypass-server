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

// prefixRelated reports whether one issuer name is a prefix of the other.
// Kafka sign lookups match `issuer_type LIKE name || '%'` and prefer the
// later expiry, so such a pair would silently route one to the other.
func prefixRelated(a, b string) bool {
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
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
       i.last_rotated_at, r.stop_issuing_at, r.replacement_issuer_id, r.retired_by,
       (SELECT count(*) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id),
       (SELECT max(end_at) FROM v3_issuer_keys k WHERE k.issuer_id = i.issuer_id)
FROM v3_issuers i
LEFT JOIN issuer_retirements r ON r.issuer_id = i.issuer_id`

type rowScanner interface{ Scan(dest ...any) error }

func scanAdminIssuer(row rowScanner, now time.Time) (adminapi.Issuer, error) {
	var (
		out                                  adminapi.Issuer
		duration, replacement, retiredBy     sql.NullString
		created, validFrom, expires, rotated pq.NullTime
		stopIssuing, latestEnd               pq.NullTime
	)
	err := row.Scan(&out.ID, &out.Name, &out.Version, &out.Cohort, &out.MaxTokens,
		&out.Buffer, &out.Overlap, &duration, &created, &validFrom, &expires,
		&rotated, &stopIssuing, &replacement, &retiredBy, &out.KeyCount, &latestEnd)
	if err != nil {
		return out, err
	}
	if duration.Valid && duration.String != "" {
		out.Duration = &duration.String
	}
	if replacement.Valid {
		out.ReplacementID = &replacement.String
	}
	if retiredBy.Valid {
		out.RetiredBy = &retiredBy.String
	}
	out.CreatedAt = nullableTime(created)
	out.ValidFrom = nullableTime(validFrom)
	out.ExpiresAt = nullableTime(expires)
	out.LastRotatedAt = nullableTime(rotated)
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

	// Signing keys are never selected here.
	rows, err := c.db.QueryContext(ctx, `
        SELECT key_id, public_key, cohort, created_at, start_at, end_at
        FROM v3_issuer_keys WHERE issuer_id = $1
        ORDER BY end_at ASC NULLS FIRST, start_at ASC, created_at ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k adminapi.Key
		var pub sql.NullString
		var created, start, end pq.NullTime
		if err := rows.Scan(&k.ID, &pub, &k.Cohort, &created, &start, &end); err != nil {
			return nil, err
		}
		k.PublicKey = pub.String
		k.CreatedAt, k.StartAt, k.EndAt = nullableTime(created), nullableTime(start), nullableTime(end)
		iss.Keys = append(iss.Keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	replaced, err := c.db.QueryContext(ctx,
		`SELECT issuer_id FROM issuer_retirements WHERE replacement_issuer_id = $1 ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer replaced.Close()
	for replaced.Next() {
		var rid string
		if err := replaced.Scan(&rid); err != nil {
			return nil, err
		}
		iss.Replaces = append(iss.Replaces, rid)
	}
	return &iss, replaced.Err()
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

func (c *Server) adminListAudit(ctx context.Context, issuerID *uuid.UUID, limit int) ([]adminapi.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := c.db.QueryContext(ctx, `
        SELECT id, created_at, operator, action, issuer_id, request
        FROM issuer_admin_audit
        WHERE ($1::uuid IS NULL OR issuer_id = $1)
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

// withAdminTx runs fn in a transaction, rolling back on any error.
func (c *Server) withAdminTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()
	return fn(tx)
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
		ExpiresAt:    pq.NullTime{Valid: true}, // matches the existing "no expiry" encoding
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
			now := time.Now()
			iss.ValidFrom = &now
		}
		d := req.Duration
		iss.Duration = &d
	}

	var id uuid.UUID
	err := c.withAdminTx(ctx, func(tx *sql.Tx) error {
		var clash string
		err := tx.QueryRowContext(ctx, `
            SELECT issuer_type FROM v3_issuers
            WHERE issuer_type <> $1
              AND (left(issuer_type, length($1)) = $1 OR left($1, length(issuer_type)) = issuer_type)
            LIMIT 1`, req.Name).Scan(&clash)
		if err == nil {
			return ruleErr("name %q and existing issuer %q are prefixes of one another; Kafka resolves issuers by prefix, so pick a name that is not", req.Name, clash)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if id, err = txCreateV3Issuer(c.Logger, tx, iss); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "create", &id, req)
	})
	return id, err
}

type lockedIssuer struct {
	id            uuid.UUID
	name          string
	version       int
	buffer        int
	overlap       int
	duration      sql.NullString
	validFrom     pq.NullTime
	expiresAt     pq.NullTime
	stopIssuingAt *time.Time
}

func (l lockedIssuer) status(now time.Time) adminapi.Status {
	return adminapi.DeriveStatus(now, nullableTime(l.expiresAt), l.stopIssuingAt)
}

func txSelectIssuersForUpdate(ctx context.Context, tx *sql.Tx, ids []uuid.UUID) (map[uuid.UUID]*lockedIssuer, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT i.issuer_id, i.issuer_type, i.version, i.buffer, i.overlap, i.duration, i.valid_from, i.expires_at
        FROM v3_issuers i WHERE i.issuer_id = ANY($1)
        ORDER BY i.issuer_id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]*lockedIssuer{}
	for rows.Next() {
		l := &lockedIssuer{}
		if err := rows.Scan(&l.id, &l.name, &l.version, &l.buffer, &l.overlap, &l.duration, &l.validFrom, &l.expiresAt); err != nil {
			return nil, err
		}
		out[l.id] = l
	}
	return out, rows.Err()
}

// txLockIssuers locks the given issuer rows in id order (deadlock-safe) and
// returns them keyed by id. Missing ids → errAdminNotFound.
func txLockIssuers(ctx context.Context, tx *sql.Tx, ids ...uuid.UUID) (map[uuid.UUID]*lockedIssuer, error) {
	// The rows must be closed before the per-issuer queries below run on the
	// same transaction, hence the separate function.
	out, err := txSelectIssuersForUpdate(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		l, ok := out[id]
		if !ok {
			return nil, errAdminNotFound
		}
		var stop pq.NullTime
		err := tx.QueryRowContext(ctx, `SELECT stop_issuing_at FROM issuer_retirements WHERE issuer_id = $1`, id).Scan(&stop)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		l.stopIssuingAt = nullableTime(stop)
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
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
		if err != nil {
			return err
		}
		l := locked[id]
		if req.ExpiresAt != nil {
			cur := nullableTime(l.expiresAt)
			if cur == nil {
				return ruleErr("issuer has no expiry; setting one would shorten it")
			}
			if !req.ExpiresAt.After(*cur) {
				return ruleErr("expires_at can only extend (current %s)", cur.UTC().Format(time.RFC3339))
			}
			if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, *req.ExpiresAt); err != nil {
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

// latestWindowEnd is the furthest v3 key end that can exist if the rotation
// cron keeps running until stopIssuing.
func latestWindowEnd(l *lockedIssuer, currentMax *time.Time, stopIssuing time.Time) (time.Time, error) {
	end := stopIssuing
	if l.duration.Valid && l.duration.String != "" {
		d, err := timeutils.ParseDuration(l.duration.String)
		if err != nil {
			return time.Time{}, err
		}
		for i := 0; i < l.buffer+l.overlap; i++ {
			next, err := d.From(end)
			if err != nil {
				return time.Time{}, err
			}
			end = *next
		}
	}
	if currentMax != nil && currentMax.After(end) {
		end = *currentMax
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
	if stopRedeeming.Before(stopIssuing.Add(adminapi.MinRetirementOverlap)) {
		return ruleErr("stop_redeeming_at must be at least 90 days after stop_issuing_at")
	}

	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
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
		if prefixRelated(target.name, repl.name) {
			return ruleErr("issuer %q and replacement %q are prefixes of one another; Kafka resolves issuers by prefix and would route one to the other", target.name, repl.name)
		}
		if exp := nullableTime(repl.expiresAt); exp != nil && exp.Before(stopRedeeming) {
			return ruleErr("replacement expires at %s, before stop_redeeming_at", exp.UTC().Format(time.RFC3339))
		}
		if vf := nullableTime(repl.validFrom); vf != nil && vf.Truncate(time.Second).After(stopIssuing) {
			return ruleErr("replacement valid_from %s is after stop_issuing_at", vf.UTC().Format(time.RFC3339))
		}

		// Chain rule: if the target is itself the replacement for an issuer
		// that still redeems, it must keep issuing until that one stops.
		var promised pq.NullTime
		err = tx.QueryRowContext(ctx, `
            SELECT max(i.expires_at) FROM issuer_retirements r
            JOIN v3_issuers i ON i.issuer_id = r.issuer_id
            WHERE r.replacement_issuer_id = $1 AND i.expires_at > $2`, id, now).Scan(&promised)
		if err != nil {
			return err
		}
		if p := nullableTime(promised); p != nil && stopIssuing.Before(*p) {
			return ruleErr("stop_issuing_at is before %s, the overlap promised to the issuer this one replaces", p.UTC().Format(time.RFC3339))
		}

		if target.version >= 3 {
			var maxEnd pq.NullTime
			if err := tx.QueryRowContext(ctx, `SELECT max(end_at) FROM v3_issuer_keys WHERE issuer_id = $1`, id).Scan(&maxEnd); err != nil {
				return err
			}
			need, err := latestWindowEnd(target, nullableTime(maxEnd), stopIssuing)
			if err != nil {
				return err
			}
			if stopRedeeming.Before(need) {
				return ruleErr("stop_redeeming_at must be at or after %s, the last key window that can be issued", need.UTC().Format(time.RFC3339))
			}
		}

		if _, err := tx.ExecContext(ctx, `
            INSERT INTO issuer_retirements
                (issuer_id, replacement_issuer_id, stop_issuing_at, expires_at_before_retire, retired_by)
            VALUES ($1, $2, $3, $4, $5)`,
			id, replID, stopIssuing, target.expiresAt, operator); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, stopRedeeming); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "retire", &id, adminapi.RetireRequest{
			ReplacementIssuerID: req.ReplacementIssuerID, StopIssuingAt: stopIssuing, StopRedeemingAt: stopRedeeming,
		})
	})
}

// adminPostponeRetirement moves stop_issuing_at later on a retiring or
// retired issuer: the emergency switch when clients still depend on it.
// It never shortens redemption and keeps the replacement's promise.
func (c *Server) adminPostponeRetirement(ctx context.Context, operator string, id uuid.UUID, req adminapi.PostponeRequest, now time.Time) error {
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
		locked, err := txLockIssuers(ctx, tx, id)
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
		req.StopIssuingAt = req.StopIssuingAt.UTC().Truncate(time.Second)
		if req.StopRedeemingAt != nil {
			t := req.StopRedeemingAt.UTC().Truncate(time.Second)
			req.StopRedeemingAt = &t
		}
		if !req.StopIssuingAt.After(*l.stopIssuingAt) || req.StopIssuingAt.Before(now.Truncate(time.Second)) {
			return ruleErr("stop_issuing_at must be later than the current %s and not in the past", l.stopIssuingAt.UTC().Format(time.RFC3339))
		}
		cur := nullableTime(l.expiresAt) // retired issuers always have one
		redeem := req.StopIssuingAt.Add(adminapi.MinRetirementOverlap)
		if cur != nil && cur.After(redeem) {
			redeem = *cur
		}
		if req.StopRedeemingAt != nil {
			if cur != nil && req.StopRedeemingAt.Before(*cur) {
				return ruleErr("stop_redeeming_at would shorten redemption (current %s)", cur.UTC().Format(time.RFC3339))
			}
			if req.StopRedeemingAt.Before(req.StopIssuingAt.Add(adminapi.MinRetirementOverlap)) {
				return ruleErr("stop_redeeming_at must be at least 90 days after stop_issuing_at")
			}
			redeem = *req.StopRedeemingAt
		}
		// v3: tokens are signed for future windows and the cron keeps adding
		// keys until the new stop_issuing_at, so cover the furthest one.
		if l.version >= 3 {
			var maxEnd pq.NullTime
			if err := tx.QueryRowContext(ctx, `SELECT max(end_at) FROM v3_issuer_keys WHERE issuer_id = $1`, id).Scan(&maxEnd); err != nil {
				return err
			}
			need, err := latestWindowEnd(l, nullableTime(maxEnd), req.StopIssuingAt)
			if err != nil {
				return err
			}
			if req.StopRedeemingAt != nil && req.StopRedeemingAt.Before(need) {
				return ruleErr("stop_redeeming_at must be at or after %s, the last key window that can be issued", need.UTC().Format(time.RFC3339))
			}
			if redeem.Before(need) {
				redeem = need
			}
		}

		// Replacement must still issue through the (possibly longer) window.
		var replExpires, replStop pq.NullTime
		err = tx.QueryRowContext(ctx, `
            SELECT i.expires_at, rr.stop_issuing_at
            FROM issuer_retirements r
            JOIN v3_issuers i ON i.issuer_id = r.replacement_issuer_id
            LEFT JOIN issuer_retirements rr ON rr.issuer_id = r.replacement_issuer_id
            WHERE r.issuer_id = $1`, id).Scan(&replExpires, &replStop)
		if err != nil {
			return err
		}
		if e := nullableTime(replExpires); e != nil && e.Before(redeem) {
			return ruleErr("replacement expires at %s, before the new stop_redeeming_at; extend it first", e.UTC().Format(time.RFC3339))
		}
		if s := nullableTime(replStop); s != nil && s.Before(redeem) {
			return ruleErr("replacement stops issuing at %s, before the new stop_redeeming_at; postpone it first", s.UTC().Format(time.RFC3339))
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issuer_retirements SET stop_issuing_at = $2 WHERE issuer_id = $1`, id, req.StopIssuingAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, redeem); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "postpone", &id, req)
	})
}

func (c *Server) adminCancelRetirement(ctx context.Context, operator string, id uuid.UUID, now time.Time) error {
	return c.withAdminTx(ctx, func(tx *sql.Tx) error {
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
		// Never shorten: keep the later of the pre-retire value and the
		// current one; the no-expiry sentinel wins.
		restore := before
		if b, cur := nullableTime(before), nullableTime(locked[id].expiresAt); b != nil && cur != nil && cur.After(*b) {
			restore = locked[id].expiresAt
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_issuers SET expires_at = $2 WHERE issuer_id = $1`, id, restore); err != nil {
			return err
		}
		return txInsertAudit(ctx, tx, operator, "cancel_retire", &id, map[string]string{"issuer_id": id.String()})
	})
}
