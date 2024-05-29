package model

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

var (
	ErrInvalidIssuerType   = errors.New("model: invalid issuer type")
	ErrInvalidIV3Key       = errors.New("model: issuer_v3: invalid key")
	ErrIssuerV3NoCryptoKey = errors.New("model: issuer_v3: no crypto signing key for period")
)

// Issuer represents an issuer of tokens.
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

func (x *Issuer) ExpiresAtTime() time.Time {
	if !x.ExpiresAt.Valid {
		return time.Time{}
	}

	return x.ExpiresAt.Time
}

func (x *Issuer) HasExpired(now time.Time) bool {
	expt := x.ExpiresAtTime()

	return !expt.IsZero() && expt.Before(now)
}

func (x *Issuer) FindSigningKeys(now time.Time) ([]*crypto.SigningKey, error) {
	if x.Version != 3 {
		return nil, ErrInvalidIssuerType
	}

	const leeway = 1 * time.Hour

	keys, err := x.findActiveKeys(now, leeway)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, nil
	}

	return parseSigningKeys(keys), nil
}

// findActiveKeys finds active keys in x.Keys that are active for time now.
//
// It searches for strictly matching key first, and places it at the first position of the result.
// Then it searches for keys that match with leeway lw.
// The strictly matching key is excluded from search with lw.
func (x *Issuer) findActiveKeys(now time.Time, lw time.Duration) ([]*IssuerKeys, error) {
	var result []*IssuerKeys

	for i := range x.Keys {
		active, err := x.Keys[i].isActiveV3(now, 0)
		if err != nil {
			return nil, err
		}

		if active {
			result = append([]*IssuerKeys{&x.Keys[i]}, result...)
			continue
		}

		activeLw, err := x.Keys[i].isActiveV3(now, lw)
		if err != nil {
			return nil, err
		}

		if activeLw {
			result = append(result, &x.Keys[i])
		}
	}

	return result, nil
}

func parseSigningKeys(keys []*IssuerKeys) []*crypto.SigningKey {
	result := make([]*crypto.SigningKey, 0, len(keys))

	for i := range keys {
		if key := keys[i].CryptoSigningKey(); key != nil {
			result = append(result, key)
		}
	}

	return result
}
