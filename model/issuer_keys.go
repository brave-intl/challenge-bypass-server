package model

import (
	"time"

	"github.com/google/uuid"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

// IssuerKeys represents time-based keys.
type IssuerKeys struct {
	ID         *uuid.UUID `json:"id" db:"key_id"`
	SigningKey []byte     `json:"-" db:"signing_key"`
	PublicKey  *string    `json:"public_key" db:"public_key"`
	Cohort     int16      `json:"cohort" db:"cohort"`
	IssuerID   *uuid.UUID `json:"issuer_id" db:"issuer_id"`
	CreatedAt  *time.Time `json:"created_at" db:"created_at"`
	StartAt    *time.Time `json:"start_at" db:"start_at"`
	EndAt      *time.Time `json:"end_at" db:"end_at"`
}

func (x *IssuerKeys) CryptoSigningKey() *crypto.SigningKey {
	result := &crypto.SigningKey{}
	if err := result.UnmarshalText(x.SigningKey); err != nil {
		return nil
	}

	return result
}

func (x *IssuerKeys) isActiveV3(now time.Time, lw time.Duration) (bool, error) {
	if !x.isValidV3() {
		return false, ErrInvalidIV3Key
	}

	start, end := *x.StartAt, *x.EndAt
	if lw == 0 {
		return isTimeWithin(start, end, now), nil
	}

	// Shift start/end earlier/later by lw, respectively.
	return isTimeWithin(start.Add(-1*lw), end.Add(lw), now), nil
}

func (x *IssuerKeys) isValidV3() bool {
	return x.StartAt != nil && x.EndAt != nil
}

func isTimeWithin(start, end, now time.Time) bool {
	return now.After(start) && now.Before(end)
}
