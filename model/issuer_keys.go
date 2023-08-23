package model

import (
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/google/uuid"
	"time"
)

// IssuerKeys - an issuer that uses time based keys
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

func (key *IssuerKeys) CryptoSigningKey() *crypto.SigningKey {
	cryptoSigningKey := crypto.SigningKey{}
	err := cryptoSigningKey.UnmarshalText(key.SigningKey)
	if err != nil {
		return nil
	}

	return &cryptoSigningKey
}
