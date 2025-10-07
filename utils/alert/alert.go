package alert

import (
	"context"
	"log/slog"
	"strings"
)

// Alert formats a special log entry to be detected by a log filter to trigger a Slack
// alert.
func Alert(ctx context.Context, logger *slog.Logger, err error, alertType AlertType) {
	logger.Log(ctx, slog.LevelError, "",
		slog.String("code", alertType.String()),
		slog.String("message", err.Error()),
	)
}

type AlertType int

const (
	Outage AlertType = iota
	Crash
	Generic
)

// String returns the string representation of an AlertType
func (s AlertType) String() string {
	switch s {
	case Crash:
		return "ALERT_CRASH"
	case Outage:
		return "ALERT_OUTAGE"
	case Generic:
		return "ALERT_TEAM"
	default:
		return "ALERT_TEAM"
	}
}

// ParseAlertType converts a string to a AlertType
func ParseAlertType(s string) AlertType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "alert_crash":
		return Crash
	case "alert_outage":
		return Outage
	case "alert_team":
		return Generic
	default:
		return Generic
	}
}

// MarshalText implements the encoding.TextMarshaler interface
func (s AlertType) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (s *AlertType) UnmarshalText(text []byte) error {
	*s = ParseAlertType(string(text))
	return nil
}
