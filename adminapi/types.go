// Package adminapi holds the wire types, request signer and client for the
// challenge-bypass-server /v1/admin API. It must stay cgo-free so the
// cbp-manage TUI builds without the ristretto library.
package adminapi

import (
	"encoding/json"
	"time"
)

// MinRetirementOverlap is the minimum time a retired issuer keeps redeeming
// after it stops issuing, while its replacement issues.
const MinRetirementOverlap = 90 * 24 * time.Hour

type Status string

const (
	StatusActive   Status = "active"   // issuing and redeeming
	StatusRetiring Status = "retiring" // retirement scheduled, still issuing
	StatusRetired  Status = "retired"  // redeem-only
	StatusExpired  Status = "expired"  // neither
)

// DeriveStatus computes an issuer's status. A nil expiresAt means no expiry.
func DeriveStatus(now time.Time, expiresAt, stopIssuingAt *time.Time) Status {
	switch {
	case expiresAt != nil && expiresAt.Before(now):
		return StatusExpired
	case stopIssuingAt == nil:
		return StatusActive
	case stopIssuingAt.After(now):
		return StatusRetiring
	default:
		return StatusRetired
	}
}

type Key struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Cohort    int16      `json:"cohort"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	StartAt   *time.Time `json:"start_at,omitempty"`
	EndAt     *time.Time `json:"end_at,omitempty"`
}

type Issuer struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Version       int        `json:"version"`
	Cohort        int16      `json:"cohort"`
	MaxTokens     int        `json:"max_tokens"`
	Buffer        int        `json:"buffer"`
	Overlap       int        `json:"overlap"`
	Duration      *string    `json:"duration,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"` // nil = no expiry
	LastRotatedAt *time.Time `json:"last_rotated_at,omitempty"`
	Status        Status     `json:"status"`
	StopIssuingAt *time.Time `json:"stop_issuing_at,omitempty"`
	ReplacementID *string    `json:"replacement_issuer_id,omitempty"`
	RetiredBy     *string    `json:"retired_by,omitempty"`
	Replaces      []string   `json:"replaces,omitempty"`
	KeyCount      int        `json:"key_count"`
	LatestKeyEnd  *time.Time `json:"latest_key_end,omitempty"`
	Keys          []Key      `json:"keys,omitempty"`
}

type ListIssuersResponse struct {
	Issuers []Issuer `json:"issuers"`
}

type CreateIssuerRequest struct {
	Name      string     `json:"name"`
	Version   int        `json:"version"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ValidFrom *time.Time `json:"valid_from,omitempty"` // v3 only
	Duration  string     `json:"duration,omitempty"`   // v3 only, ISO 8601
	Buffer    int        `json:"buffer,omitempty"`     // v3 only
	Overlap   int        `json:"overlap,omitempty"`    // v3 only
}

// UpdateIssuerRequest: only these fields are mutable. The server rejects
// unknown fields.
type UpdateIssuerRequest struct {
	MaxTokens *int       `json:"max_tokens,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // extend only
}

type RetireRequest struct {
	ReplacementIssuerID string    `json:"replacement_issuer_id"`
	StopIssuingAt       time.Time `json:"stop_issuing_at"`
	StopRedeemingAt     time.Time `json:"stop_redeeming_at"`
}

// PostponeRequest moves stop_issuing_at later on a retiring or retired
// issuer (the emergency switch). StopRedeemingAt nil = server keeps the
// later of the current value and StopIssuingAt + 90 days.
type PostponeRequest struct {
	StopIssuingAt   time.Time  `json:"stop_issuing_at"`
	StopRedeemingAt *time.Time `json:"stop_redeeming_at,omitempty"`
}

type AuditEntry struct {
	ID        int64           `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	Operator  string          `json:"operator"`
	Action    string          `json:"action"`
	IssuerID  *string         `json:"issuer_id,omitempty"`
	Request   json.RawMessage `json:"request"`
}

type AuditResponse struct {
	Entries []AuditEntry `json:"entries"`
}
