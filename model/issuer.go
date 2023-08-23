package model

import (
	"github.com/google/uuid"
	"github.com/lib/pq"
	"time"
)

// Issuer of tokens
type Issuer struct {
	ID                   *uuid.UUID   `json:"id" db:"issuer_id"`
	IssuerType           string       `json:"issuer_type" db:"issuer_type"`
	IssuerCohort         int16        `json:"issuer_cohort" db:"issuer_cohort"`
	SigningKey           []byte       `db:"signing_key"`
	MaxTokens            int          `json:"max_tokens" db:"max_tokens"`
	CreatedAt            pq.NullTime  `json:"created_at" db:"created_at"`
	ExpiresAt            pq.NullTime  `json:"expires_at" db:"expires_at"`
	RotatedAt            pq.NullTime  `json:"rotated_at" db:"last_rotated_at"`
	Version              int          `json:"version" db:"version"`
	ValidFrom            *time.Time   `json:"valid_from" db:"valid_from"`
	Buffer               int          `json:"buffer" db:"buffer"`
	DaysOut              int          `json:"days_out" db:"days_out"`
	Overlap              int          `json:"overlap" db:"overlap"`
	Duration             *string      `json:"duration" db:"duration"`
	RedemptionRepository string       `json:"-" db:"redemption_repository"`
	Keys                 []IssuerKeys `json:"keys" db:"-"`
}

func (iss *Issuer) ExpiresAtTime() time.Time {
	var t time.Time
	if !iss.ExpiresAt.Valid {
		return t
	}

	return iss.ExpiresAt.Time
}
