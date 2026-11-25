package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
	actmigrations "github.com/brave-intl/challenge-bypass-server/migrations/act"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	actStatusHeld       = "held"
	actStatusRefunded   = "refunded"
	actStatusRolledOver = "rolled_over"

	// actSchemaVersion is the ACT migration version this build needs.
	actSchemaVersion uint = 1

	actIssuerCacheTTL = 30 * time.Second
)

var (
	errACTIssuerNotFound = errors.New("act: issuer not found")
	errACTSpendNotFound  = errors.New("act: spend not found")
	// errACTDoubleSpend - nullifier already recorded with a different proof or idempotency key
	errACTDoubleSpend = errors.New("act: nullifier already spent")
	// errACTRefundConflict - spend already refunded at a different cost, or rolled over
	errACTRefundConflict = errors.New("act: spend already settled with a different cost")
	// errACTCostExceedsCharge - actual cost is larger than the held charge
	errACTCostExceedsCharge = errors.New("act: cost exceeds held charge")
	// errACTIssuanceConflict - issuance idempotency key already used for a different request
	errACTIssuanceConflict = errors.New("act: issuance idempotency key already used with a different request")
	// errACTRolloverNotAllowed - source issuer is not permitted to roll into target issuer
	errACTRolloverNotAllowed = errors.New("act: rollover from source issuer is not allowed")
	// errACTIssuanceStopped - issuer has passed stop_issuing_at or expires_at
	errACTIssuanceStopped = errors.New("act: issuer is no longer accepting new issuances")
	// errACTInvalidUpdate - admin update violates an ACT issuer invariant
	errACTInvalidUpdate = errors.New("act: invalid issuer update")
)

type actIssuer struct {
	ID              uuid.UUID
	Name            string
	Params          string
	Context         string
	ContextScalar   [32]byte
	PrivateKey      []byte
	PublicKey       []byte
	MaxCredits      uint64
	CreatedAt       time.Time
	StopIssuingAt   *time.Time
	ExpiresAt       time.Time
	RolloverFrom    []string
	RolloverFromIDs map[uuid.UUID]struct{}
}

func (i *actIssuer) hasExpired(now time.Time) bool { return !now.Before(i.ExpiresAt) }

func (i *actIssuer) canIssue(now time.Time) bool {
	if i.hasExpired(now) {
		return false
	}
	if i.StopIssuingAt != nil && !now.Before(*i.StopIssuingAt) {
		return false
	}
	return true
}

func (i *actIssuer) allowsRolloverFrom(sourceID uuid.UUID) bool {
	if sourceID == i.ID {
		return true
	}
	_, ok := i.RolloverFromIDs[sourceID]
	return ok
}

type actIssuerCacheEntry struct {
	issuer    *actIssuer
	expiresAt time.Time
}

// actIssuerCache is a nil-safe TTL cache for ACT issuers.
type actIssuerCache struct {
	mu      sync.RWMutex
	entries map[string]actIssuerCacheEntry
}

func (ac *actIssuerCache) get(name string, now time.Time) (*actIssuer, bool) {
	if ac == nil {
		return nil, false
	}
	ac.mu.RLock()
	e, ok := ac.entries[name]
	ac.mu.RUnlock()
	if !ok || !now.Before(e.expiresAt) {
		return nil, false
	}
	return e.issuer, true
}

func (ac *actIssuerCache) set(iss *actIssuer, now time.Time) {
	if ac == nil {
		return
	}
	ac.mu.Lock()
	if ac.entries == nil {
		ac.entries = make(map[string]actIssuerCacheEntry)
	}
	ac.entries[iss.Name] = actIssuerCacheEntry{
		issuer:    iss,
		expiresAt: now.Add(actIssuerCacheTTL),
	}
	ac.mu.Unlock()
}

type actSpend struct {
	IssuerID       uuid.UUID
	Nullifier      []byte
	ProofHash      []byte
	IdempotencyKey string
	SpendProof     []byte
	Charge         uint64
	Cost           *uint64
	Refund         []byte
	Status         string
	CreatedAt      time.Time
	RefundedAt     *time.Time
}

type actIssuance struct {
	IssuerID         uuid.UUID
	IdempotencyKey   string
	RequestHash      []byte
	PurchasedCredits uint64
	RolledCredits    uint64
	TotalCredits     uint64
	Response         []byte
	CreatedAt        time.Time
}

// verifiedRolloverProof is a rollover input verified against its source issuer
// before entering the atomic consumption + issuance transaction.
type verifiedRolloverProof struct {
	SourceID  uuid.UUID
	Nullifier [32]byte
	ProofHash [32]byte
	Charge    uint64
}

// migrateACT applies the ACT schema up to actSchemaVersion using migrateSchema
// so rolling back to an older build skips when the DB is ahead. It uses its
// own migrations table so versions never interleave with the main sequence.
func migrateACT(db *sql.DB, logger *slog.Logger) error {
	src, err := iofs.New(actmigrations.FS, ".")
	if err != nil {
		return err
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{MigrationsTable: "act_schema_migrations"})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return err
	}
	return migrateSchema(m, actSchemaVersion, logger)
}

func txResolveRolloverSources(ctx context.Context, tx *sql.Tx, names []string) (map[string]uuid.UUID, error) {
	resolved := make(map[string]uuid.UUID, len(names))
	if len(names) == 0 {
		return resolved, nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT issuer_id, name FROM act_issuers WHERE name = ANY($1)`,
		pq.Array(names))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		resolved[name] = id
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, ok := resolved[name]; !ok {
			return nil, fmt.Errorf("%w: rollover source %q", errACTIssuerNotFound, name)
		}
	}
	return resolved, nil
}

func (c *Server) createACTIssuer(ctx context.Context, operator string, iss *actIssuer, rolloverFrom []string, auditReq any) error {
	ctxScalar, err := act.Context([]byte(iss.Context))
	if err != nil {
		return err
	}
	iss.ContextScalar = ctxScalar

	if err := c.withTx(ctx, func(tx *sql.Tx) error {
		if operator != "" {
			if err := txInsertAudit(ctx, tx, operator, "create_act_issuer", nil, auditReq); err != nil {
				return err
			}
		}
		var stopAt sql.NullTime
		if iss.StopIssuingAt != nil {
			stopAt = sql.NullTime{Time: iss.StopIssuingAt.UTC(), Valid: true}
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO act_issuers (name, params, context, private_key, public_key, max_credits, stop_issuing_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING issuer_id, created_at`,
			iss.Name, iss.Params, iss.Context, iss.PrivateKey, iss.PublicKey,
			int64(iss.MaxCredits), stopAt, iss.ExpiresAt.UTC(),
		).Scan(&iss.ID, &iss.CreatedAt); err != nil {
			return err
		}

		sources, err := txResolveRolloverSources(ctx, tx, rolloverFrom)
		if err != nil {
			return err
		}
		iss.RolloverFromIDs = make(map[uuid.UUID]struct{}, len(sources))
		iss.RolloverFrom = make([]string, 0, len(sources))
		for name, srcID := range sources {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO act_issuer_rollovers (target_issuer_id, source_issuer_id)
				VALUES ($1, $2)
				ON CONFLICT DO NOTHING`,
				iss.ID, srcID); err != nil {
				return err
			}
			iss.RolloverFromIDs[srcID] = struct{}{}
			iss.RolloverFrom = append(iss.RolloverFrom, name)
		}
		slices.Sort(iss.RolloverFrom)
		return nil
	}); err != nil {
		return err
	}
	c.actCache.set(iss, time.Now())
	return nil
}

func (c *Server) updateACTIssuer(
	ctx context.Context,
	operator, name string,
	stopIssuingAt, expiresAt *time.Time,
	addRolloverFrom, removeRolloverFrom []string,
	auditReq any,
) (*actIssuer, error) {
	var updated *actIssuer
	err := c.withTx(ctx, func(tx *sql.Tx) error {
		if operator != "" {
			if err := txInsertAudit(ctx, tx, operator, "update_act_issuer", nil, auditReq); err != nil {
				return err
			}
		}
		var (
			iss        actIssuer
			maxCredits int64
			curStop    sql.NullTime
		)
		err := tx.QueryRowContext(ctx, `
			SELECT issuer_id, name, params, context, private_key, public_key, max_credits, created_at, stop_issuing_at, expires_at
			FROM act_issuers WHERE name = $1 FOR UPDATE`, name,
		).Scan(&iss.ID, &iss.Name, &iss.Params, &iss.Context, &iss.PrivateKey, &iss.PublicKey,
			&maxCredits, &iss.CreatedAt, &curStop, &iss.ExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return errACTIssuerNotFound
		}
		if err != nil {
			return err
		}
		iss.MaxCredits = uint64(maxCredits)
		if curStop.Valid {
			t := curStop.Time
			iss.StopIssuingAt = &t
		}

		newExpires := iss.ExpiresAt
		if expiresAt != nil {
			u := expiresAt.UTC()
			if u.Before(iss.ExpiresAt) {
				return fmt.Errorf("%w: expires_at can only move later", errACTInvalidUpdate)
			}
			newExpires = u
		}

		newStop := iss.StopIssuingAt
		if stopIssuingAt != nil {
			u := stopIssuingAt.UTC()
			newStop = &u
		}
		if newStop != nil && newStop.After(newExpires) {
			return fmt.Errorf("%w: stop_issuing_at must be at or before expires_at", errACTInvalidUpdate)
		}

		var stopParam sql.NullTime
		if newStop != nil {
			stopParam = sql.NullTime{Time: *newStop, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE act_issuers SET stop_issuing_at = $1, expires_at = $2
			WHERE issuer_id = $3`,
			stopParam, newExpires, iss.ID); err != nil {
			return err
		}
		iss.StopIssuingAt = newStop
		iss.ExpiresAt = newExpires

		if len(addRolloverFrom) > 0 {
			sources, err := txResolveRolloverSources(ctx, tx, addRolloverFrom)
			if err != nil {
				return err
			}
			for srcName, srcID := range sources {
				if srcID == iss.ID {
					return fmt.Errorf("%w: issuer %q cannot list itself in add_rollover_from", errACTInvalidUpdate, srcName)
				}
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO act_issuer_rollovers (target_issuer_id, source_issuer_id)
					VALUES ($1, $2)
					ON CONFLICT DO NOTHING`,
					iss.ID, srcID); err != nil {
					return err
				}
			}
		}

		if len(removeRolloverFrom) > 0 {
			sources, err := txResolveRolloverSources(ctx, tx, removeRolloverFrom)
			if err != nil {
				return err
			}
			removeIDs := make([]uuid.UUID, 0, len(sources))
			for _, srcID := range sources {
				removeIDs = append(removeIDs, srcID)
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM act_issuer_rollovers
				WHERE target_issuer_id = $1 AND source_issuer_id = ANY($2)`,
				iss.ID, pq.Array(removeIDs)); err != nil {
				return err
			}
		}

		rollNames, rollIDs, err := fetchRolloverSources(ctx, tx, iss.ID)
		if err != nil {
			return err
		}
		ctxScalar, err := act.Context([]byte(iss.Context))
		if err != nil {
			return err
		}
		iss.ContextScalar = ctxScalar
		iss.RolloverFrom = rollNames
		iss.RolloverFromIDs = rollIDs
		updated = &iss
		return nil
	})
	if err != nil {
		return nil, err
	}
	c.actCache.set(updated, time.Now())
	return updated, nil
}

type queryExecutor interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func fetchRolloverSources(ctx context.Context, q queryExecutor, targetID uuid.UUID) ([]string, map[uuid.UUID]struct{}, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT r.source_issuer_id, i.name
		FROM act_issuer_rollovers r
		JOIN act_issuers i ON i.issuer_id = r.source_issuer_id
		WHERE r.target_issuer_id = $1
		ORDER BY i.name ASC`, targetID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	ids := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
		ids[id] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	return names, ids, rows.Err()
}

func (c *Server) listACTIssuers(ctx context.Context) ([]actIssuer, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT issuer_id, name, params, context, public_key, max_credits, created_at, stop_issuing_at, expires_at
		FROM act_issuers
		ORDER BY created_at DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []actIssuer{}
	for rows.Next() {
		var (
			iss        actIssuer
			maxCredits int64
			stopAt     sql.NullTime
		)
		if err := rows.Scan(&iss.ID, &iss.Name, &iss.Params, &iss.Context, &iss.PublicKey,
			&maxCredits, &iss.CreatedAt, &stopAt, &iss.ExpiresAt); err != nil {
			return nil, err
		}
		iss.MaxCredits = uint64(maxCredits)
		if stopAt.Valid {
			t := stopAt.Time
			iss.StopIssuingAt = &t
		}
		out = append(out, iss)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return out, nil
	}
	rollRows, err := c.db.QueryContext(ctx, `
		SELECT r.target_issuer_id, i.name
		FROM act_issuer_rollovers r
		JOIN act_issuers i ON i.issuer_id = r.source_issuer_id
		ORDER BY i.name ASC`)
	if err != nil {
		return nil, err
	}
	defer rollRows.Close()
	byTarget := map[uuid.UUID][]string{}
	for rollRows.Next() {
		var targetID uuid.UUID
		var srcName string
		if err := rollRows.Scan(&targetID, &srcName); err != nil {
			return nil, err
		}
		byTarget[targetID] = append(byTarget[targetID], srcName)
	}
	if err := rollRows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].RolloverFrom = byTarget[out[i].ID]
	}
	return out, nil
}

// fetchACTIssuer returns the named ACT issuer, using a short TTL cache and
// reading from the writer on miss so newly created issuers never hit replica lag.
func (c *Server) fetchACTIssuer(ctx context.Context, name string) (*actIssuer, error) {
	now := time.Now()
	if iss, ok := c.actCache.get(name, now); ok {
		return iss, nil
	}

	var (
		iss        actIssuer
		maxCredits int64
		stopAt     sql.NullTime
	)
	err := c.db.QueryRowContext(ctx, `
		SELECT issuer_id, name, params, context, private_key, public_key, max_credits, created_at, stop_issuing_at, expires_at
		FROM act_issuers WHERE name = $1`, name,
	).Scan(&iss.ID, &iss.Name, &iss.Params, &iss.Context, &iss.PrivateKey, &iss.PublicKey,
		&maxCredits, &iss.CreatedAt, &stopAt, &iss.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errACTIssuerNotFound
	}
	if err != nil {
		return nil, err
	}
	if stopAt.Valid {
		t := stopAt.Time
		iss.StopIssuingAt = &t
	}
	rollNames, rollIDs, err := fetchRolloverSources(ctx, c.db, iss.ID)
	if err != nil {
		return nil, err
	}
	ctxScalar, err := act.Context([]byte(iss.Context))
	if err != nil {
		return nil, err
	}
	iss.ContextScalar = ctxScalar
	iss.MaxCredits = uint64(maxCredits)
	iss.RolloverFrom = rollNames
	iss.RolloverFromIDs = rollIDs
	c.actCache.set(&iss, now)
	return &iss, nil
}

const actIssuanceColumns = `issuer_id, idempotency_key, request_hash, purchased_credits, rolled_credits, total_credits, response, created_at`

func scanACTIssuance(row rowScanner) (*actIssuance, error) {
	var (
		issuance                         actIssuance
		purchased, rolled, totalCredits  int64
	)
	err := row.Scan(&issuance.IssuerID, &issuance.IdempotencyKey, &issuance.RequestHash,
		&purchased, &rolled, &totalCredits, &issuance.Response, &issuance.CreatedAt)
	if err != nil {
		return nil, err
	}
	issuance.PurchasedCredits = uint64(purchased)
	issuance.RolledCredits = uint64(rolled)
	issuance.TotalCredits = uint64(totalCredits)
	return &issuance, nil
}

func (c *Server) fetchACTIssuance(ctx context.Context, issuerID uuid.UUID, idempotencyKey string) (*actIssuance, error) {
	issuance, err := scanACTIssuance(c.db.QueryRowContext(ctx,
		`SELECT `+actIssuanceColumns+` FROM act_issuances WHERE issuer_id = $1 AND idempotency_key = $2`,
		issuerID, idempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return issuance, err
}

// executeACTIssuance atomically consumes all verified rollover nullifiers,
// signs the new IssuanceResponse, and persists the idempotency record in
// act_issuances. It returns created=true only when this call performed the
// issuance (false on an idempotent retry).
func (c *Server) executeACTIssuance(
	ctx context.Context,
	target *actIssuer,
	idempotencyKey string,
	requestHash []byte,
	issuanceReq []byte,
	purchasedCredits, rolledCredits uint64,
	rollovers []verifiedRolloverProof,
) (*actIssuance, bool, error) {
	// Sort rollover proofs deterministically by (source_id, nullifier) so
	// concurrent multi-proof rollovers cannot deadlock on act_spends locks.
	sorted := make([]verifiedRolloverProof, len(rollovers))
	copy(sorted, rollovers)
	slices.SortFunc(sorted, func(a, b verifiedRolloverProof) int {
		if d := bytes.Compare(a.SourceID[:], b.SourceID[:]); d != 0 {
			return d
		}
		return bytes.Compare(a.Nullifier[:], b.Nullifier[:])
	})

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	rolloverIdem := "rollover:" + target.ID.String() + ":" + idempotencyKey
	for _, r := range sorted {
		var inserted []byte
		err := tx.QueryRowContext(ctx, `
			INSERT INTO act_spends (issuer_id, nullifier, proof_hash, idempotency_key, spend_proof, charge, cost, refund, status, refunded_at)
			VALUES ($1, $2, $3, $4, NULL, $5, $5, NULL, $6, now())
			ON CONFLICT (issuer_id, nullifier) DO NOTHING
			RETURNING nullifier`,
			r.SourceID, r.Nullifier[:], r.ProofHash[:], rolloverIdem, int64(r.Charge), actStatusRolledOver,
		).Scan(&inserted)
		if errors.Is(err, sql.ErrNoRows) {
			// Either a genuine double-spend/double-rollover, or a concurrent
			// retry with the exact same idempotency_key just committed.
			_ = tx.Rollback()
			existing, ferr := c.fetchACTIssuance(ctx, target.ID, idempotencyKey)
			if ferr != nil {
				return nil, false, ferr
			}
			if existing != nil {
				if !bytes.Equal(existing.RequestHash, requestHash) {
					return nil, false, errACTIssuanceConflict
				}
				return existing, false, nil
			}
			return nil, false, errACTDoubleSpend
		}
		if err != nil {
			return nil, false, err
		}
	}

	totalCredits := purchasedCredits + rolledCredits
	respBytes, err := act.Issue(target.Params, target.PrivateKey, issuanceReq, totalCredits, []byte(target.Context))
	if err != nil {
		return nil, false, err
	}

	issuance, err := scanACTIssuance(tx.QueryRowContext(ctx, `
		INSERT INTO act_issuances (issuer_id, idempotency_key, request_hash, purchased_credits, rolled_credits, total_credits, response)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (issuer_id, idempotency_key) DO NOTHING
		RETURNING `+actIssuanceColumns,
		target.ID, idempotencyKey, requestHash,
		int64(purchasedCredits), int64(rolledCredits), int64(totalCredits), respBytes))
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		existing, ferr := c.fetchACTIssuance(ctx, target.ID, idempotencyKey)
		if ferr != nil {
			return nil, false, ferr
		}
		if existing == nil || !bytes.Equal(existing.RequestHash, requestHash) {
			return nil, false, errACTIssuanceConflict
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return issuance, true, nil
}

const actSpendColumns = `issuer_id, nullifier, proof_hash, idempotency_key, spend_proof, charge, cost, refund, status, created_at, refunded_at`

func scanACTSpend(row rowScanner) (*actSpend, error) {
	var s actSpend
	var charge int64
	var cost sql.NullInt64
	var refundedAt sql.NullTime
	err := row.Scan(&s.IssuerID, &s.Nullifier, &s.ProofHash, &s.IdempotencyKey, &s.SpendProof,
		&charge, &cost, &s.Refund, &s.Status, &s.CreatedAt, &refundedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errACTSpendNotFound
	}
	if err != nil {
		return nil, err
	}
	s.Charge = uint64(charge)
	if cost.Valid {
		v := uint64(cost.Int64)
		s.Cost = &v
	}
	if refundedAt.Valid {
		s.RefundedAt = &refundedAt.Time
	}
	return &s, nil
}

func (c *Server) fetchACTSpend(ctx context.Context, issuerID uuid.UUID, nullifier []byte) (*actSpend, error) {
	return scanACTSpend(c.db.QueryRowContext(ctx,
		`SELECT `+actSpendColumns+` FROM act_spends WHERE issuer_id = $1 AND nullifier = $2`,
		issuerID, nullifier))
}

// recordACTHold atomically records a verified spend's nullifier as a hold.
//
// A retry carrying both the identical proof hash and the identical origin
// idempotency key returns the existing record (with created=false) so the
// calling service can safely retry. Any other proof or idempotency key for the
// same nullifier is a double spend (including a client replaying the same
// proof across requests, or a credential already consumed by rollover).
func (c *Server) recordACTHold(ctx context.Context, issuerID uuid.UUID, info act.SpendInfo, proof, proofHash []byte, idempotencyKey string) (*actSpend, bool, error) {
	spend, err := scanACTSpend(c.db.QueryRowContext(ctx, `
		INSERT INTO act_spends (issuer_id, nullifier, proof_hash, idempotency_key, spend_proof, charge)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (issuer_id, nullifier) DO NOTHING
		RETURNING `+actSpendColumns,
		issuerID, info.Nullifier[:], proofHash, idempotencyKey, proof, int64(info.Charge)))
	if !errors.Is(err, errACTSpendNotFound) {
		return spend, err == nil, err
	}

	existing, err := c.fetchACTSpend(ctx, issuerID, info.Nullifier[:])
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(existing.ProofHash, proofHash) || existing.IdempotencyKey != idempotencyKey {
		return nil, false, errACTDoubleSpend
	}
	return existing, false, nil
}

// finalizeACTSpend settles a hold at `cost` credits and stores the refund for
// the remaining `charge - cost`. It is idempotent for the same cost and
// returns settledNow=true only when this call transitioned the row from held.
func (c *Server) finalizeACTSpend(ctx context.Context, iss *actIssuer, nullifier []byte, cost uint64) (*actSpend, bool, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	spend, err := scanACTSpend(tx.QueryRowContext(ctx,
		`SELECT `+actSpendColumns+` FROM act_spends WHERE issuer_id = $1 AND nullifier = $2 FOR UPDATE`,
		iss.ID, nullifier))
	if err != nil {
		return nil, false, err
	}

	if spend.Status == actStatusRolledOver {
		return spend, false, errACTRefundConflict
	}
	if spend.Status == actStatusRefunded {
		if spend.Cost == nil || *spend.Cost != cost {
			return spend, false, errACTRefundConflict
		}
		return spend, false, nil
	}

	if err := settleACTSpend(ctx, tx, iss, spend, cost); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return spend, true, nil
}

// settleACTSpend issues the refund for a locked, held spend, clears the stored
// spend_proof (no longer needed once refunded), and marks the row refunded.
func settleACTSpend(ctx context.Context, tx *sql.Tx, iss *actIssuer, spend *actSpend, cost uint64) error {
	if cost > spend.Charge {
		return errACTCostExceedsCharge
	}
	refund, err := act.Refund(iss.Params, iss.PrivateKey, spend.SpendProof, spend.Charge-cost)
	if err != nil {
		return fmt.Errorf("issue refund: %w", err)
	}

	var refundedAt time.Time
	if err := tx.QueryRowContext(ctx, `
		UPDATE act_spends
		SET status = $1, cost = $2, refund = $3, spend_proof = NULL, refunded_at = now()
		WHERE issuer_id = $4 AND nullifier = $5
		RETURNING refunded_at`,
		actStatusRefunded, int64(cost), refund, spend.IssuerID, spend.Nullifier,
	).Scan(&refundedAt); err != nil {
		return err
	}

	spend.Status = actStatusRefunded
	spend.Cost = &cost
	spend.Refund = refund
	spend.SpendProof = nil
	spend.RefundedAt = &refundedAt
	return nil
}

// actSweepCursor marks the last row scanned by sweepACTHoldsPage so later
// batches within a tick advance past failing rows even when an entire page
// fails to settle.
type actSweepCursor struct {
	createdAt time.Time
	issuerID  uuid.UUID
	nullifier []byte
	set       bool
}

// sweepACTHoldsPage settles one keyset-paginated batch of holds older than
// olderThan at zero cost, returning the full charge to the client. Each hold
// is claimed and committed in its own short transaction with FOR UPDATE SKIP
// LOCKED so failing rows cannot roll back other rows, and returning the last
// scanned cursor lets callers advance past poison-pill pages.
//
// ponytail: settles at cost 0 (user-favourable). If abandoned holds get abused,
// charge a flat fee or make timeout cost configurable per issuer instead.
func (c *Server) sweepACTHoldsPage(ctx context.Context, olderThan time.Duration, limit int, after actSweepCursor) (int, int, actSweepCursor, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if after.set {
		rows, err = c.db.QueryContext(ctx, `
			SELECT issuer_id, nullifier, created_at
			FROM act_spends
			WHERE status = 'held'
			  AND created_at < now() - make_interval(secs => $1)
			  AND (created_at, issuer_id, nullifier) > ($2, $3, $4)
			ORDER BY created_at, issuer_id, nullifier
			LIMIT $5`,
			olderThan.Seconds(), after.createdAt, after.issuerID, after.nullifier, limit)
	} else {
		rows, err = c.db.QueryContext(ctx, `
			SELECT issuer_id, nullifier, created_at
			FROM act_spends
			WHERE status = 'held' AND created_at < now() - make_interval(secs => $1)
			ORDER BY created_at, issuer_id, nullifier
			LIMIT $2`,
			olderThan.Seconds(), limit)
	}
	if err != nil {
		return 0, 0, actSweepCursor{}, err
	}
	defer rows.Close()

	type candidate struct {
		issuerID  uuid.UUID
		nullifier []byte
		createdAt time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var k candidate
		if err := rows.Scan(&k.issuerID, &k.nullifier, &k.createdAt); err != nil {
			return 0, 0, actSweepCursor{}, err
		}
		candidates = append(candidates, k)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, actSweepCursor{}, err
	}
	if err := rows.Err(); err != nil {
		return 0, 0, actSweepCursor{}, err
	}

	var next actSweepCursor
	if len(candidates) > 0 {
		last := candidates[len(candidates)-1]
		next = actSweepCursor{
			createdAt: last.createdAt,
			issuerID:  last.issuerID,
			nullifier: last.nullifier,
			set:       true,
		}
	}

	var (
		settled  int
		firstErr error
	)
	for _, k := range candidates {
		if ctx.Err() != nil {
			return len(candidates), settled, next, ctx.Err()
		}
		issName, sweptCharge, ok, err := c.sweepOneACTHold(ctx, k.issuerID, k.nullifier)
		if err != nil {
			actCallTotal.WithLabelValues("sweep", "error").Inc()
			if c.Logger != nil {
				c.Logger.Error("act: sweep hold failed", slog.String("issuer_id", k.issuerID.String()), slog.Any("error", err))
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ok {
			settled++
			actCreditsTotal.WithLabelValues(issName, "swept").Add(float64(sweptCharge))
			actCreditsTotal.WithLabelValues(issName, "refunded").Add(float64(sweptCharge))
		}
	}
	return len(candidates), settled, next, firstErr
}

func (c *Server) sweepOneACTHold(ctx context.Context, issuerID uuid.UUID, nullifier []byte) (string, uint64, bool, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		spend  actSpend
		iss    actIssuer
		charge int64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT s.issuer_id, s.nullifier, s.spend_proof, s.charge, i.name, i.params, i.private_key
		FROM act_spends s JOIN act_issuers i USING (issuer_id)
		WHERE s.issuer_id = $1 AND s.nullifier = $2 AND s.status = 'held'
		FOR UPDATE OF s SKIP LOCKED`,
		issuerID, nullifier,
	).Scan(&spend.IssuerID, &spend.Nullifier, &spend.SpendProof, &charge, &iss.Name, &iss.Params, &iss.PrivateKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	spend.Charge = uint64(charge)

	if err := settleACTSpend(ctx, tx, &iss, &spend, 0); err != nil {
		return "", 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, false, err
	}
	return iss.Name, spend.Charge, true, nil
}

// dedupeStrings returns a sorted, deduplicated slice of non-empty strings.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
