package server

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupCronTasks_function_injection(t *testing.T) {
	hourTicker := make(chan time.Time, 5) // Increase buffer size
	minuteTicker := make(chan time.Time, 5)

	var rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount int
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	initialTime := time.Date(2025, 6, 10, 12, 30, 0, 0, time.UTC)

	// Add debugging
	debug := func(format string, args ...interface{}) {
		fmt.Printf("DEBUG: "+format+"\n", args...)
	}

	server := &Server{
		Logger: logger,
		Now: func() time.Time {
			return initialTime
		},
		Sleep: func(d time.Duration) {
			debug("Sleep called with duration: %v", d)
		},
		NewTicker: func(d time.Duration) <-chan time.Time {
			debug("NewTicker called with duration: %v", d)
			if d == time.Hour {
				return hourTicker
			} else if d == time.Minute {
				return minuteTicker
			}
			panic("Unexpected ticker duration")
		},
		RotateIssuers: func() error {
			rotateIssuersCount++
			debug("RotateIssuers called, count=%d", rotateIssuersCount)
			return nil
		},
		DeleteIssuerKeys: func(period string) (int64, error) {
			deleteIssuerKeysCount++
			debug("DeleteIssuerKeys called, count=%d", deleteIssuerKeysCount)
			return 42, nil
		},
		RotateIssuersV3: func() error {
			rotateIssuersV3Count++
			debug("RotateIssuersV3 called, count=%d", rotateIssuersV3Count)
			return nil
		},
	}

	debug("Starting SetupCronTasks")
	server.SetupCronTasks()
	debug("SetupCronTasks returned")

	// Wait for initial calls to complete
	debug("Waiting for initial calls")
	require.Eventually(t, func() bool {
		result := rotateIssuersCount == 1 &&
			rotateIssuersV3Count == 1 &&
			deleteIssuerKeysCount == 1
		debug("Initial wait check: rotateIssuers=%d, rotateIssuersV3=%d, deleteIssuerKeys=%d, result=%v",
			rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount, result)
		return result
	}, 3*time.Second, 100*time.Millisecond)

	debug("After initial wait, counters: rotateIssuers=%d, rotateIssuersV3=%d, deleteIssuerKeys=%d",
		rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount)

	assert.Equal(t, 1, rotateIssuersCount)
	assert.Equal(t, 1, rotateIssuersV3Count)
	assert.Equal(t, 1, deleteIssuerKeysCount)

	// Send first round of ticks
	debug("Sending hour tick")
	hourTicker <- initialTime.Add(time.Hour)
	debug("Sending minute tick")
	minuteTicker <- initialTime.Add(time.Minute)

	debug("Waiting for second round of calls")
	require.Eventually(t, func() bool {
		result := rotateIssuersCount == 2 &&
			rotateIssuersV3Count == 2 &&
			deleteIssuerKeysCount == 2
		debug("Second wait check: rotateIssuers=%d, rotateIssuersV3=%d, deleteIssuerKeys=%d, result=%v",
			rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount, result)
		return result
	}, 3*time.Second, 100*time.Millisecond)

	debug("After second wait, counters: rotateIssuers=%d, rotateIssuersV3=%d, deleteIssuerKeys=%d",
		rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount)

	assert.Equal(t, 2, rotateIssuersCount)
	assert.Equal(t, 2, deleteIssuerKeysCount)
	assert.Equal(t, 2, rotateIssuersV3Count)

	// Send one more hour tick
	debug("Sending third hour tick")
	hourTicker <- initialTime.Add(2 * time.Hour)

	debug("Waiting for hourly job's third call")
	require.Eventually(t, func() bool {
		result := rotateIssuersCount == 3 && deleteIssuerKeysCount == 3
		debug("Third wait check: rotateIssuers=%d, deleteIssuerKeys=%d, result=%v",
			rotateIssuersCount, deleteIssuerKeysCount, result)
		return result
	}, 3*time.Second, 100*time.Millisecond)

	debug("After third wait, counters: rotateIssuers=%d, deleteIssuerKeys=%d",
		rotateIssuersCount, deleteIssuerKeysCount)

	assert.Equal(t, 3, rotateIssuersCount)
	assert.Equal(t, 3, deleteIssuerKeysCount)

	// Send one more minute tick
	debug("Sending third minute tick")
	minuteTicker <- initialTime.Add(2 * time.Minute)

	debug("Waiting for minute job's third call")
	require.Eventually(t, func() bool {
		result := rotateIssuersV3Count == 3
		debug("Fourth wait check: rotateIssuersV3=%d, result=%v",
			rotateIssuersV3Count, result)
		return result
	}, 3*time.Second, 100*time.Millisecond)

	debug("Final state: rotateIssuers=%d, rotateIssuersV3=%d, deleteIssuerKeys=%d",
		rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount)

	assert.Equal(t, 3, rotateIssuersV3Count)
}
