package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupCronTasks_function_injection(t *testing.T) {
	var rotateIssuersCount, rotateIssuersV3Count, deleteIssuerKeysCount int
	var mu sync.Mutex // Protect concurrent access to counters

	// Use a time very close to the next minute so initial wait is short
	initialTime := time.Date(2025, 6, 10, 12, 30, 59, 500000000, time.UTC) // 500ms before next minute

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go SetupCronTasks(
		ctx,
		initialTime,
		[]Task{
			{
				Interval: 1 * time.Second,
				Execute: func() error {
					mu.Lock()
					rotateIssuersCount++
					deleteIssuerKeysCount++
					mu.Unlock()
					return nil
				},
			},
			{
				Interval: 1 * time.Second,
				Execute: func() error {
					mu.Lock()
					rotateIssuersV3Count++
					mu.Unlock()
					return nil
				},
			},
		},
	)

	// Wait for initial execution (after ~500ms initial wait)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rotateIssuersCount >= 1 &&
			rotateIssuersV3Count >= 1 &&
			deleteIssuerKeysCount >= 1
	}, 2*time.Second, 100*time.Millisecond)

	// Wait for second execution (after 1 second interval)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rotateIssuersCount >= 2 &&
			rotateIssuersV3Count >= 2 &&
			deleteIssuerKeysCount >= 2
	}, 2*time.Second, 100*time.Millisecond)

	// Wait for third execution (after another 1 second interval)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rotateIssuersCount >= 3 &&
			rotateIssuersV3Count >= 3 &&
			deleteIssuerKeysCount >= 3
	}, 2*time.Second, 100*time.Millisecond)

	mu.Lock()
	assert.GreaterOrEqual(t, rotateIssuersCount, 3)
	assert.GreaterOrEqual(t, rotateIssuersV3Count, 3)
	assert.GreaterOrEqual(t, deleteIssuerKeysCount, 3)
	mu.Unlock()
}
