package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
)

func TestAlertTypeString(t *testing.T) {
	tests := []struct {
		name      string
		alertType AlertType
		expected  string
	}{
		{"Crash", Crash, "ALERT_CRASH"},
		{"Outage", Outage, "ALERT_OUTAGE"},
		{"Generic", Generic, "ALERT_TEAM"},
		{"Default", AlertType(999), "ALERT_TEAM"}, // Test default case
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alertType.String(); got != tt.expected {
				t.Errorf("AlertType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseAlertType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected AlertType
	}{
		{"crash lowercase", "alert_crash", Crash},
		{"crash uppercase", "ALERT_CRASH", Crash},
		{"crash spaced", "  alert_crash  ", Crash},
		{"crash mixed case", "Alert_Crash", Crash},
		{"outage lowercase", "alert_outage", Outage},
		{"outage uppercase", "ALERT_OUTAGE", Outage},
		{"outage spaced", "  alert_outage  ", Outage},
		{"generic lowercase", "alert_team", Generic},
		{"generic uppercase", "ALERT_TEAM", Generic},
		{"generic spaced", "  alert_team  ", Generic},
		{"unknown random", "random", Generic},
		{"unknown empty", "", Generic},
		{"unknown only spaces", "   ", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseAlertType(tt.input); got != tt.expected {
				t.Errorf("ParseAlertType(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAlertTypeMarshalText(t *testing.T) {
	tests := []struct {
		name      string
		alertType AlertType
		expected  string
	}{
		{"Crash", Crash, "ALERT_CRASH"},
		{"Outage", Outage, "ALERT_OUTAGE"},
		{"Generic", Generic, "ALERT_TEAM"},
		{"Default", AlertType(999), "ALERT_TEAM"}, // Test default case
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.alertType.MarshalText()
			if err != nil {
				t.Errorf("AlertType.MarshalText() error = %v", err)
				return
			}
			if string(got) != tt.expected {
				t.Errorf("AlertType.MarshalText() = %q, want %q", string(got), tt.expected)
			}
		})
	}
}

func TestAlertTypeUnmarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected AlertType
	}{
		{"crash lowercase", "alert_crash", Crash},
		{"crash uppercase", "ALERT_CRASH", Crash},
		{"crash spaced", "  alert_crash  ", Crash},
		{"outage lowercase", "alert_outage", Outage},
		{"outage uppercase", "ALERT_OUTAGE", Outage},
		{"outage spaced", "  alert_outage  ", Outage},
		{"generic lowercase", "alert_team", Generic},
		{"generic uppercase", "ALERT_TEAM", Generic},
		{"generic spaced", "  alert_team  ", Generic},
		{"unknown random", "random", Generic},
		{"unknown empty", "", Generic},
		{"unknown only spaces", "   ", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var at AlertType
			err := at.UnmarshalText([]byte(tt.input))
			if err != nil {
				t.Errorf("AlertType.UnmarshalText(%q) error = %v", tt.input, err)
				return
			}
			if at != tt.expected {
				t.Errorf("AlertType.UnmarshalText(%q) set value to %v, want %v", tt.input, at, tt.expected)
			}
		})
	}
}

func TestAlert(t *testing.T) {
	tests := []struct {
		name        string
		alertType   AlertType
		wantCode    string
		wantMessage string
	}{
		{"Crash", Crash, "ALERT_CRASH", "test error"},
		{"Outage", Outage, "ALERT_OUTAGE", "test error"},
		{"Generic", Generic, "ALERT_TEAM", "test error"},
		{"Default", AlertType(999), "ALERT_TEAM", "test error"}, // Default behavior
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a buffer to capture the log output
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
			logger := slog.New(handler)

			// Call the Alert function
			testErr := errors.New(tt.wantMessage)
			Alert(logger, testErr, tt.alertType)

			// Parse the JSON log entry
			var logEntry map[string]any
			if err := json.NewDecoder(&buf).Decode(&logEntry); err != nil {
				t.Fatalf("Failed to decode log entry: %v", err)
			}

			// Verify the log level
			if level := logEntry["level"]; level != "ERROR" {
				t.Errorf("Log level = %v, want %q", level, "ERROR")
			}

			// Verify the main message is an empty string (keyed as "msg" in JSON handler)
			if msg := logEntry["msg"]; msg != nil && msg != "" {
				t.Errorf("Log main message = %v, want empty or nil", msg)
			}

			// Verify the structured "code" field
			if code := logEntry["code"]; code != tt.wantCode {
				t.Errorf("Log code = %v, want %q", code, tt.wantCode)
			}

			// Verify the structured "message" field
			if structuredMsg := logEntry["message"]; structuredMsg != tt.wantMessage {
				t.Errorf("Log structured message = %v, want %q", structuredMsg, tt.wantMessage)
			}

			// Ensure expected fields: time, level, msg, code, message
			if len(logEntry) != 5 {
				t.Errorf("Unexpected number of fields in log entry: %d, logEntry: %v", len(logEntry), logEntry)
			}
		})
	}
}

// Edge case: Test Alert with nil logger (expects panic)
func TestAlertNilLogger(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic with nil logger, but did not")
		}
	}()
	Alert(nil, errors.New("test"), Crash)
}

// Edge case: Test Alert with nil error (expects panic on err.Error())
func TestAlertNilError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	logger := slog.New(handler)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic with nil error, but did not")
		}
	}()
	Alert(logger, nil, Generic) // This will panic on nil.Error()
}
