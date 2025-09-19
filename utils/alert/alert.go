package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Alert formats a special log entry to be detected by a log filter to trigger a Slack
// alert.
func Alert(logger *slog.Logger, err error, severityString string) {
	messageBytes, fmtErr := formatMessageForSlack(err, ParseSeverity(severityString))
	if fmtErr != nil {
		messageBytes = []byte(err.Error() + "\nError alert formatting failed with err:\n" + fmtErr.Error())
	}
	logger.Log(context.Background(), slog.LevelError, "",
		slog.String("code", "ALERT_TEAM"),
		slog.String("message", string(messageBytes)),
	)
}

type SlackMessage struct {
	Attachments []Attachment `json:"attachments"`
}

type Attachment struct {
	Color  string  `json:"color"`
	Blocks []Block `json:"blocks"`
}

type Block map[string]any

func formatMessageForSlack(err error, severity Severity) ([]byte, error) {
	// Create the rich error message
	message := SlackMessage{
		Attachments: []Attachment{
			{
				Color: "danger",
				Blocks: []Block{
					{
						"type": "header",
						"text": map[string]any{
							"type":  "plain_text",
							"text":  "🚨" + os.Getenv("ENV") + " Error Alert",
							"emoji": true,
						},
					},
					{
						"type": "section",
						"fields": []map[string]string{
							{
								"type": "mrkdwn",
								"text": fmt.Sprintf("*Environment:*\n%s", os.Getenv("ENV")),
							},
							{
								"type": "mrkdwn",
								"text": fmt.Sprintf("*Severity:*\n%s", severity),
							},
						},
					},
					{"type": "divider"},
					{
						"type": "section",
						"text": map[string]string{
							"type": "mrkdwn",
							"text": fmt.Sprintf("*Error Message:*\n```%s```", err.Error()),
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal slack message: %w", err)
	}

	return jsonData, err
}

type Severity int

const (
	SeverityImpaired Severity = iota
	SeverityDown
	SeverityRisk
	SeverityUnknown
)

// String returns the string representation of a Severity
func (s Severity) String() string {
	switch s {
	case SeverityImpaired:
		return "impaired"
	case SeverityDown:
		return "down"
	case SeverityRisk:
		return "risk"
	case SeverityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to a Severity
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "impaired":
		return SeverityImpaired
	case "down":
		return SeverityDown
	case "risk":
		return SeverityRisk
	case "unknown":
		return SeverityUnknown
	default:
		return SeverityUnknown
	}
}

// MarshalText implements the encoding.TextMarshaler interface
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (s *Severity) UnmarshalText(text []byte) error {
	*s = ParseSeverity(string(text))
	return nil
}
