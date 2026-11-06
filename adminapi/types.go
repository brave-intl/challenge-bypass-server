// Package adminapi holds the wire types, request signer and client for the
// challenge-bypass-server /v1/admin API. It must stay cgo-free so the
// cbp-manage TUI builds without the ristretto library.
package adminapi

import (
	"encoding/json"
	"time"

	timeutils "github.com/brave-intl/bat-go/libs/time"
)

// MinStopRedeeming is the earliest stop_redeeming_at allowed for an issuer
// whose last issuance is at lastIssue. The result is the later of lastIssue
// plus 3 calendar months and lastIssue plus 90 days. Either one can be the
// later one. For example, Feb 1 plus 3 months is only 89 days.
func MinStopRedeeming(lastIssue time.Time) time.Time {
	m := lastIssue.UTC().AddDate(0, 3, 0)
	if d := lastIssue.Add(90 * 24 * time.Hour); d.After(m) {
		return d
	}
	return m
}

// WindowsEnd returns the end of n consecutive v3 key windows of the ISO 8601
// duration, the first starting at from. The windows use the same calendar
// steps as the rotation cron. An empty duration returns from.
func WindowsEnd(duration string, n int, from time.Time) (time.Time, error) {
	if duration == "" {
		return from, nil
	}
	d, err := timeutils.ParseDuration(duration)
	if err != nil {
		return time.Time{}, err
	}
	for i := 0; i < n; i++ {
		next, err := d.From(from)
		if err != nil {
			return time.Time{}, err
		}
		from = *next
	}
	return from, nil
}

type Status string

const (
	StatusActive   Status = "active"   // signs and redeems
	StatusRetiring Status = "retiring" // stop_issuing_at is in the future, still signs
	StatusRetired  Status = "retired"  // redeems only
	StatusExpired  Status = "expired"  // neither signs nor redeems
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
	Status        Status     `json:"status"`
	StopIssuingAt *time.Time `json:"stop_issuing_at,omitempty"`
	ReplacementID *string    `json:"replacement_issuer_id,omitempty"`
	LatestKeyEnd  *time.Time `json:"latest_key_end,omitempty"`
	Keys          []Key      `json:"keys,omitempty"`
}

type CreateIssuerRequest struct {
	Name      string     `json:"name"`
	Version   int        `json:"version"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
	ValidFrom *time.Time `json:"valid_from"` // v3 only
	Duration  string     `json:"duration"`   // v3 only, ISO 8601
	Buffer    int        `json:"buffer"`     // v3 only
	Overlap   int        `json:"overlap"`    // v3 only
}

// UpdateIssuerRequest holds the only mutable fields. The server rejects
// unknown fields.
type UpdateIssuerRequest struct {
	MaxTokens *int       `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"` // can only move later
}

type RetireRequest struct {
	ReplacementIssuerID string    `json:"replacement_issuer_id"`
	StopIssuingAt       time.Time `json:"stop_issuing_at"`
	StopRedeemingAt     time.Time `json:"stop_redeeming_at"`
}

// PostponeRequest moves stop_issuing_at later on a retiring or retired
// issuer. With StopRedeemingAt nil, the server uses the earliest
// stop_redeeming_at that the retirement rules allow.
type PostponeRequest struct {
	StopIssuingAt   time.Time  `json:"stop_issuing_at"`
	StopRedeemingAt *time.Time `json:"stop_redeeming_at"`
}

type WhoAmIResponse struct {
	Operator string `json:"operator"`
}

type AuditEntry struct {
	ID        int64           `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	Operator  string          `json:"operator"`
	Action    string          `json:"action"`
	IssuerID  *string         `json:"issuer_id,omitempty"`
	Request   json.RawMessage `json:"request"`
}
