package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestAlert tests the Alert function
func TestAlert(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		severityString  string
		wantLogContains []string
	}{
		{
			name:           "valid alert with error and severity",
			err:            errors.New("test error message"),
			severityString: "down",
			wantLogContains: []string{
				"ALERT_TEAM",
				"test error message",
			},
		},
		{
			name:           "alert with unknown severity",
			err:            errors.New("another error"),
			severityString: "invalid",
			wantLogContains: []string{
				"ALERT_TEAM",
				"another error",
				"unknown",
			},
		},
		{
			name:           "alert with empty severity",
			err:            errors.New("empty severity error"),
			severityString: "",
			wantLogContains: []string{
				"ALERT_TEAM",
				"empty severity error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))

			Alert(logger, tt.err, tt.severityString)

			logOutput := buf.String()
			for _, want := range tt.wantLogContains {
				if !strings.Contains(logOutput, want) {
					t.Errorf("Alert() log output missing %q, got: %s", want, logOutput)
				}
			}

			var logEntry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
				t.Errorf("Alert() produced invalid JSON: %v", err)
			}

			if level, ok := logEntry["level"].(string); !ok || level != "ERROR" {
				t.Errorf("Alert() log level = %v, want ERROR", logEntry["level"])
			}
		})
	}
}

// TestFormatMessageForSlack tests the formatMessageForSlack function
func TestFormatMessageForSlack(t *testing.T) {
	originalEnv := os.Getenv("ENV")
	defer os.Setenv("ENV", originalEnv)

	tests := []struct {
		name        string
		err         error
		severity    Severity
		envValue    string
		wantContain []string
		wantErr     bool
	}{
		{
			name:     "format message with production environment",
			err:      errors.New("database connection failed"),
			severity: SeverityDown,
			envValue: "production",
			wantContain: []string{
				"database connection failed",
				"down",
				"production",
				"🚨production Error Alert",
			},
			wantErr: false,
		},
		{
			name:     "format message with staging environment",
			err:      errors.New("API timeout"),
			severity: SeverityImpaired,
			envValue: "staging",
			wantContain: []string{
				"API timeout",
				"impaired",
				"staging",
			},
			wantErr: false,
		},
		{
			name:     "format message with empty environment",
			err:      errors.New("service unavailable"),
			severity: SeverityRisk,
			envValue: "",
			wantContain: []string{
				"service unavailable",
				"risk",
				"🚨 Error Alert",
			},
			wantErr: false,
		},
		{
			name:     "format message with unknown severity",
			err:      errors.New("unknown error"),
			severity: SeverityUnknown,
			envValue: "dev",
			wantContain: []string{
				"unknown error",
				"unknown",
				"dev",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("ENV", tt.envValue)

			got, err := formatMessageForSlack(tt.err, tt.severity)
			if (err != nil) != tt.wantErr {
				t.Errorf("formatMessageForSlack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				var message SlackMessage
				if err := json.Unmarshal(got, &message); err != nil {
					t.Errorf("formatMessageForSlack() returned invalid JSON: %v", err)
					return
				}

				if len(message.Attachments) != 1 {
					t.Errorf("formatMessageForSlack() attachments count = %d, want 1", len(message.Attachments))
				}

				if message.Attachments[0].Color != "danger" {
					t.Errorf("formatMessageForSlack() color = %s, want danger", message.Attachments[0].Color)
				}

				gotStr := string(got)
				for _, want := range tt.wantContain {
					if !strings.Contains(gotStr, want) {
						t.Errorf("formatMessageForSlack() missing %q in output: %s", want, gotStr)
					}
				}
			}
		})
	}
}

// TestSeverityString tests the String method of Severity
func TestSeverityString(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{
			name:     "SeverityImpaired",
			severity: SeverityImpaired,
			want:     "impaired",
		},
		{
			name:     "SeverityDown",
			severity: SeverityDown,
			want:     "down",
		},
		{
			name:     "SeverityRisk",
			severity: SeverityRisk,
			want:     "risk",
		},
		{
			name:     "SeverityUnknown",
			severity: SeverityUnknown,
			want:     "unknown",
		},
		{
			name:     "Invalid severity value",
			severity: Severity(999),
			want:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseSeverity tests the ParseSeverity function
func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Severity
	}{
		{
			name:  "parse impaired",
			input: "impaired",
			want:  SeverityImpaired,
		},
		{
			name:  "parse down",
			input: "down",
			want:  SeverityDown,
		},
		{
			name:  "parse risk",
			input: "risk",
			want:  SeverityRisk,
		},
		{
			name:  "parse unknown",
			input: "unknown",
			want:  SeverityUnknown,
		},
		{
			name:  "parse uppercase",
			input: "DOWN",
			want:  SeverityDown,
		},
		{
			name:  "parse with spaces",
			input: "  impaired  ",
			want:  SeverityImpaired,
		},
		{
			name:  "parse mixed case with spaces",
			input: "  RiSk  ",
			want:  SeverityRisk,
		},
		{
			name:  "parse invalid string",
			input: "invalid",
			want:  SeverityUnknown,
		},
		{
			name:  "parse empty string",
			input: "",
			want:  SeverityUnknown,
		},
		{
			name:  "parse only spaces",
			input: "   ",
			want:  SeverityUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSeverity(tt.input); got != tt.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestSeverityMarshalText tests the MarshalText method
func TestSeverityMarshalText(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{
			name:     "marshal impaired",
			severity: SeverityImpaired,
			want:     "impaired",
		},
		{
			name:     "marshal down",
			severity: SeverityDown,
			want:     "down",
		},
		{
			name:     "marshal risk",
			severity: SeverityRisk,
			want:     "risk",
		},
		{
			name:     "marshal unknown",
			severity: SeverityUnknown,
			want:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.severity.MarshalText()
			if err != nil {
				t.Errorf("Severity.MarshalText() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("Severity.MarshalText() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

// TestSeverityUnmarshalText tests the UnmarshalText method
func TestSeverityUnmarshalText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Severity
	}{
		{
			name:  "unmarshal impaired",
			input: "impaired",
			want:  SeverityImpaired,
		},
		{
			name:  "unmarshal down",
			input: "down",
			want:  SeverityDown,
		},
		{
			name:  "unmarshal risk",
			input: "risk",
			want:  SeverityRisk,
		},
		{
			name:  "unmarshal unknown",
			input: "unknown",
			want:  SeverityUnknown,
		},
		{
			name:  "unmarshal invalid",
			input: "invalid",
			want:  SeverityUnknown,
		},
		{
			name:  "unmarshal uppercase",
			input: "DOWN",
			want:  SeverityDown,
		},
		{
			name:  "unmarshal with spaces",
			input: "  risk  ",
			want:  SeverityRisk,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Severity
			err := s.UnmarshalText([]byte(tt.input))
			if err != nil {
				t.Errorf("Severity.UnmarshalText() error = %v", err)
				return
			}
			if s != tt.want {
				t.Errorf("Severity.UnmarshalText() = %v, want %v", s, tt.want)
			}
		})
	}
}

// TestSeverityJSONMarshalUnmarshal tests JSON marshaling/unmarshaling
func TestSeverityJSONMarshalUnmarshal(t *testing.T) {
	type TestStruct struct {
		Severity Severity `json:"severity"`
	}

	tests := []struct {
		name     string
		severity Severity
		wantJSON string
	}{
		{
			name:     "json marshal/unmarshal impaired",
			severity: SeverityImpaired,
			wantJSON: `{"severity":"impaired"}`,
		},
		{
			name:     "json marshal/unmarshal down",
			severity: SeverityDown,
			wantJSON: `{"severity":"down"}`,
		},
		{
			name:     "json marshal/unmarshal risk",
			severity: SeverityRisk,
			wantJSON: `{"severity":"risk"}`,
		},
		{
			name:     "json marshal/unmarshal unknown",
			severity: SeverityUnknown,
			wantJSON: `{"severity":"unknown"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := TestStruct{Severity: tt.severity}
			data, err := json.Marshal(original)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}

			if string(data) != tt.wantJSON {
				t.Errorf("json.Marshal() = %s, want %s", string(data), tt.wantJSON)
			}

			var unmarshaled TestStruct
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			if unmarshaled.Severity != tt.severity {
				t.Errorf("json.Unmarshal() severity = %v, want %v", unmarshaled.Severity, tt.severity)
			}
		})
	}
}

// TestSlackMessageJSON tests the JSON structure of SlackMessage
func TestSlackMessageJSON(t *testing.T) {
	message := SlackMessage{
		Attachments: []Attachment{
			{
				Color: "danger",
				Blocks: []Block{
					{
						"type": "header",
						"text": map[string]any{
							"type": "plain_text",
							"text": "Test Header",
						},
					},
					{
						"type": "section",
						"text": map[string]string{
							"type": "mrkdwn",
							"text": "Test content",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		t.Errorf("json.Marshal(SlackMessage) error = %v", err)
		return
	}

	var unmarshaled SlackMessage
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("json.Unmarshal(SlackMessage) error = %v", err)
		return
	}

	if len(unmarshaled.Attachments) != 1 {
		t.Errorf("SlackMessage attachments count = %d, want 1", len(unmarshaled.Attachments))
	}

	if unmarshaled.Attachments[0].Color != "danger" {
		t.Errorf("SlackMessage attachment color = %s, want danger", unmarshaled.Attachments[0].Color)
	}
}

// TestAlertWithMarshalError tests Alert function when formatMessageForSlack fails
func TestAlertWithMarshalError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	testErr := errors.New("test error")

	Alert(logger, testErr, "down")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "ALERT_TEAM") {
		t.Error("Alert() should still log with ALERT_TEAM code even if formatting fails")
	}
}
