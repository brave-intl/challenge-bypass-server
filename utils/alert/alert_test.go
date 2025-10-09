package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// TestAlert_Crash tests the Crash method
func TestAlert_Crash(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string
	}{
		{
			name:        "crash with error",
			err:         errors.New("database connection failed"),
			wantCode:    "ALERT_CRASH",
			wantMessage: "database connection failed",
		},
		{
			name:        "crash with nil error",
			err:         nil,
			wantCode:    "ALERT_CRASH",
			wantMessage: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			alert := &Alert{l: logger}
			ctx := context.Background()

			alert.Crash(ctx, tt.err)

			verifyLogOutput(t, buf.String(), tt.wantCode, tt.wantMessage)
		})
	}
}

// TestAlert_Outage tests the Outage method
func TestAlert_Outage(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string
	}{
		{
			name:        "outage with error",
			err:         errors.New("service unavailable"),
			wantCode:    "ALERT_OUTAGE",
			wantMessage: "service unavailable",
		},
		{
			name:        "outage with nil error",
			err:         nil,
			wantCode:    "ALERT_OUTAGE",
			wantMessage: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			alert := &Alert{l: logger}
			ctx := context.Background()

			alert.Outage(ctx, tt.err)

			verifyLogOutput(t, buf.String(), tt.wantCode, tt.wantMessage)
		})
	}
}

// TestAlert_Generic tests the Generic method
func TestAlert_Generic(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string
	}{
		{
			name:        "generic alert with error",
			err:         errors.New("unexpected condition"),
			wantCode:    "ALERT_TEAM",
			wantMessage: "unexpected condition",
		},
		{
			name:        "generic alert with nil error",
			err:         nil,
			wantCode:    "ALERT_TEAM",
			wantMessage: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			alert := &Alert{l: logger}
			ctx := context.Background()

			alert.Generic(ctx, tt.err)

			verifyLogOutput(t, buf.String(), tt.wantCode, tt.wantMessage)
		})
	}
}

// TestAlert_WithContext tests that context is properly passed through
func TestAlert_WithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	alert := &Alert{l: logger}

	ctx := context.WithValue(context.Background(), "test-key", "test-value")
	testErr := errors.New("test error")

	alert.Crash(ctx, testErr)

	verifyLogOutput(t, buf.String(), "ALERT_CRASH", "test error")
}

// TestAlert_AllMethods tests all alert methods to ensure they use correct codes
func TestAlert_AllMethods(t *testing.T) {
	testCases := []struct {
		name     string
		method   func(*Alert, context.Context, error)
		wantCode string
	}{
		{
			name:     "Crash method",
			method:   (*Alert).Crash,
			wantCode: "ALERT_CRASH",
		},
		{
			name:     "Outage method",
			method:   (*Alert).Outage,
			wantCode: "ALERT_OUTAGE",
		},
		{
			name:     "Generic method",
			method:   (*Alert).Generic,
			wantCode: "ALERT_TEAM",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			alert := &Alert{l: logger}
			ctx := context.Background()
			testErr := errors.New("test error")

			tc.method(alert, ctx, testErr)

			verifyLogOutput(t, buf.String(), tc.wantCode, "test error")
		})
	}
}

// TestAlert_LogLevel tests that all alerts are logged at ERROR level
func TestAlert_LogLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	alert := &Alert{l: logger}
	ctx := context.Background()
	testErr := errors.New("test error")

	alert.Crash(ctx, testErr)

	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if level, ok := logEntry["level"].(string); !ok || level != "ERROR" {
		t.Errorf("Expected log level ERROR, got %v", logEntry["level"])
	}
}

// Helper function to verify log output
func verifyLogOutput(t *testing.T, output, expectedCode, expectedMessage string) {
	t.Helper()

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v\nOutput: %s", err, output)
	}

	if code, ok := logEntry["code"].(string); !ok || code != expectedCode {
		t.Errorf("Expected code %q, got %v", expectedCode, logEntry["code"])
	}

	message := logEntry["message"]
	switch v := message.(type) {
	case string:
		if v != expectedMessage {
			t.Errorf("Expected message %q, got %q", expectedMessage, v)
		}
	case nil:
		if expectedMessage != "null" {
			t.Errorf("Expected message %q, got nil", expectedMessage)
		}
	case map[string]any:
		if errMsg, ok := v["error"].(string); ok {
			if !strings.Contains(errMsg, expectedMessage) && expectedMessage != "null" {
				t.Errorf("Expected message to contain %q, got %q", expectedMessage, errMsg)
			}
		}
	default:
		t.Errorf("Unexpected message type: %T", v)
	}

	if level, ok := logEntry["level"].(string); !ok || level != "ERROR" {
		t.Errorf("Expected level ERROR, got %v", logEntry["level"])
	}
}
