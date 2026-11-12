package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	actStatusHeld     = "held"
	actStatusRefunded = "refunded"
)

var (
	errACTIssuerNotFound = errors.New("act: issuer not found")
	errACTSpendNotFound  = errors.New("act: spend not found")
	// errACTDoubleSpend - nullifier already recorded with a different proof
	errACTDoubleSpend = errors.New("act: nullifier already spent")
	// errACTRefundConflict - spend already refunded at a different cost
	errACTRefundConflict = errors.New("act: spend already refunded with a different cost")
	// errACTCostExceedsCharge - actual cost is larger than the held charge
	errACTCostExceedsCharge = errors.New("act: cost exceeds held charge")
)

type actIssuer struct {
	ID         uuid.UUID
	Name       string
	Params     string
	Context    string
	PrivateKey []byte
	PublicKey  []byte
	MaxCredits uint64
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

func (i *actIssuer) hasExpired(now time.Time) bool { return !now.Before(i.ExpiresAt) }

type actSpend struct {
	IssuerID   uuid.UUID
	Nullifier  []byte
	SpendProof []byte
	Charge     uint64
	Cost       *uint64
	Refund     []byte
	Status     string
	CreatedAt  time.Time
	RefundedAt *time.Time
}

// migrateACT applies the ACT schema. It uses its own migrations table so its
// versions never interleave with the main migrations sequence.
func migrateACT(db *sql.DB) error {
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
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func (c *Server) createACTIssuer(ctx context.Context, iss *actIssuer) error {
	return c.db.QueryRowContext(ctx, `
		INSERT INTO act_issuers (name, params, context, private_key, public_key, max_credits, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING issuer_id, created_at`,
		iss.Name, iss.Params, iss.Context, iss.PrivateKey, iss.PublicKey, int64(iss.MaxCredits), iss.ExpiresAt,
	).Scan(&iss.ID, &iss.CreatedAt)
}

// ponytail: uncached DB read per request; spend verification (~ms of EC math)
// dominates. Add a cache (see CacheCollection) if this shows up in profiles.
func (c *Server) fetchACTIssuer(ctx context.Context, name string) (*actIssuer, error) {
	var iss actIssuer
	var maxCredits int64
	err := c.dbr.QueryRowContext(ctx, `
		SELECT issuer_id, name, params, context, private_key, public_key, max_credits, created_at, expires_at
		FROM act_issuers WHERE name = $1`, name,
	).Scan(&iss.ID, &iss.Name, &iss.Params, &iss.Context, &iss.PrivateKey, &iss.PublicKey,
		&maxCredits, &iss.CreatedAt, &iss.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errACTIssuerNotFound
	}
	iss.MaxCredits = uint64(maxCredits)
	return &iss, err
}

const actSpendColumns = `issuer_id, nullifier, spend_proof, charge, cost, refund, status, created_at, refunded_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanACTSpend(row rowScanner) (*actSpend, error) {
	var s actSpend
	var charge int64
	var cost sql.NullInt64
	var refundedAt pq.NullTime
	err := row.Scan(&s.IssuerID, &s.Nullifier, &s.SpendProof, &charge, &cost, &s.Refund,
		&s.Status, &s.CreatedAt, &refundedAt)
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
// A retry carrying the byte-identical proof returns the existing record, so
// clients and the calling service can safely retry. Any other proof for the
// same nullifier is a double spend.
func (c *Server) recordACTHold(ctx context.Context, issuerID uuid.UUID, info act.SpendInfo, proof []byte) (*actSpend, error) {
	spend, err := scanACTSpend(c.db.QueryRowContext(ctx, `
		INSERT INTO act_spends (issuer_id, nullifier, spend_proof, charge)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (issuer_id, nullifier) DO NOTHING
		RETURNING `+actSpendColumns,
		issuerID, info.Nullifier[:], proof, int64(info.Charge)))
	if !errors.Is(err, errACTSpendNotFound) {
		return spend, err
	}

	existing, err := c.fetchACTSpend(ctx, issuerID, info.Nullifier[:])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(existing.SpendProof, proof) {
		return nil, errACTDoubleSpend
	}
	return existing, nil
}

// finalizeACTSpend settles a hold at `cost` credits and stores the refund for
// the remaining `charge - cost`. It is idempotent for the same cost.
func (c *Server) finalizeACTSpend(ctx context.Context, iss *actIssuer, nullifier []byte, cost uint64) (*actSpend, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	spend, err := scanACTSpend(tx.QueryRowContext(ctx,
		`SELECT `+actSpendColumns+` FROM act_spends WHERE issuer_id = $1 AND nullifier = $2 FOR UPDATE`,
		iss.ID, nullifier))
	if err != nil {
		return nil, err
	}

	if spend.Status == actStatusRefunded {
		if spend.Cost == nil || *spend.Cost != cost {
			return spend, errACTRefundConflict
		}
		return spend, nil
	}

	if err := settleACTSpend(ctx, tx, iss, spend, cost); err != nil {
		return nil, err
	}
	return spend, tx.Commit()
}

// settleACTSpend issues the refund for a locked, held spend and marks it refunded.
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
		UPDATE act_spends SET status = $1, cost = $2, refund = $3, refunded_at = now()
		WHERE issuer_id = $4 AND nullifier = $5
		RETURNING refunded_at`,
		actStatusRefunded, int64(cost), refund, spend.IssuerID, spend.Nullifier,
	).Scan(&refundedAt); err != nil {
		return err
	}

	spend.Status = actStatusRefunded
	spend.Cost = &cost
	spend.Refund = refund
	spend.RefundedAt = &refundedAt
	return nil
}

// SweepACTHolds settles holds older than olderThan at zero cost, returning
// the full charge to the client. This covers callers that crashed or never
// reported a cost; the client fetches the refund with GET .../spend/{nullifier}.
//
// ponytail: settles at cost 0 (user-favourable). If abandoned holds get abused,
// charge a flat fee here instead.
func (c *Server) SweepACTHolds(ctx context.Context, olderThan time.Duration, limit int) (int, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT s.issuer_id, s.nullifier, s.spend_proof, s.charge, s.cost, s.refund, s.status, s.created_at, s.refunded_at,
		       i.params, i.private_key
		FROM act_spends s JOIN act_issuers i USING (issuer_id)
		WHERE s.status = 'held' AND s.created_at < now() - make_interval(secs => $1)
		ORDER BY s.created_at
		LIMIT $2
		FOR UPDATE OF s SKIP LOCKED`,
		olderThan.Seconds(), limit)
	if err != nil {
		return 0, err
	}

	type held struct {
		spend *actSpend
		iss   actIssuer
	}
	var batch []held
	for rows.Next() {
		var h held
		var charge int64
		var cost sql.NullInt64
		var refundedAt pq.NullTime
		h.spend = &actSpend{}
		if err := rows.Scan(&h.spend.IssuerID, &h.spend.Nullifier, &h.spend.SpendProof, &charge, &cost,
			&h.spend.Refund, &h.spend.Status, &h.spend.CreatedAt, &refundedAt,
			&h.iss.Params, &h.iss.PrivateKey); err != nil {
			rows.Close()
			return 0, err
		}
		h.spend.Charge = uint64(charge)
		batch = append(batch, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, h := range batch {
		if err := settleACTSpend(ctx, tx, &h.iss, h.spend, 0); err != nil {
			return 0, err
		}
	}
	return len(batch), tx.Commit()
}
