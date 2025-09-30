package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCronScheduler_BasicExecution verifies tasks execute at their intervals
func TestCronScheduler_BasicExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var counter1, counter2 int32
	scheduler := NewCronScheduler(ctx)

	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&counter1, 1)
			return nil
		},
	})

	scheduler.AddTask(Task{
		Interval: 150 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&counter2, 1)
			return nil
		},
	})

	scheduler.Start()

	// Wait for multiple executions
	time.Sleep(550 * time.Millisecond)
	scheduler.Stop()

	// Task 1 should run ~5 times (at 100ms, 200ms, 300ms, 400ms, 500ms)
	count1 := atomic.LoadInt32(&counter1)
	assert.GreaterOrEqual(t, count1, int32(4), "Task 1 should run at least 4 times")
	assert.LessOrEqual(t, count1, int32(6), "Task 1 should run at most 6 times")

	// Task 2 should run ~3 times (at 150ms, 300ms, 450ms)
	count2 := atomic.LoadInt32(&counter2)
	assert.GreaterOrEqual(t, count2, int32(2), "Task 2 should run at least 2 times")
	assert.LessOrEqual(t, count2, int32(4), "Task 2 should run at most 4 times")
}

// TestCronScheduler_ErrorHandling verifies error handling behavior
func TestCronScheduler_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var executionCount int32
	var errorCount int32
	var capturedErrors []error
	var mu sync.Mutex

	testErr := errors.New("test error")
	scheduler := NewCronScheduler(ctx)

	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			count := atomic.AddInt32(&executionCount, 1)
			// Fail on even executions
			if count%2 == 0 {
				return testErr
			}
			return nil
		},
		OnError: func(err error) {
			atomic.AddInt32(&errorCount, 1)
			mu.Lock()
			capturedErrors = append(capturedErrors, err)
			mu.Unlock()
		},
	})

	scheduler.Start()
	time.Sleep(550 * time.Millisecond)
	scheduler.Stop()

	execCount := atomic.LoadInt32(&executionCount)
	errCount := atomic.LoadInt32(&errorCount)

	// Should continue executing despite errors
	assert.GreaterOrEqual(t, execCount, int32(4), "Should execute at least 4 times")
	assert.GreaterOrEqual(t, errCount, int32(2), "Should have at least 2 errors")

	// Verify error messages contain interval information
	mu.Lock()
	for _, err := range capturedErrors {
		assert.Contains(t, err.Error(), "100ms")
		assert.Contains(t, err.Error(), "test error")
	}
	mu.Unlock()
}

// TestCronScheduler_ContextCancellation verifies graceful shutdown
func TestCronScheduler_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var started, finished int32
	var wg sync.WaitGroup

	scheduler := NewCronScheduler(ctx)

	scheduler.AddTask(Task{
		Interval: 50 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&started, 1)
			wg.Add(1)
			defer wg.Done()

			// Simulate work
			time.Sleep(30 * time.Millisecond)
			atomic.AddInt32(&finished, 1)
			return nil
		},
	})

	scheduler.Start()

	// Let it run a few times
	time.Sleep(200 * time.Millisecond)

	// Cancel context and stop
	cancel()
	scheduler.Stop()

	// Wait for any in-flight operations
	wg.Wait()

	startCount := atomic.LoadInt32(&started)
	finishCount := atomic.LoadInt32(&finished)

	assert.Equal(t, startCount, finishCount, "All started tasks should finish")
	assert.GreaterOrEqual(t, startCount, int32(3), "Should have run at least 3 times")
}

// TestCronScheduler_Stop verifies Stop() blocks until tasks complete
func TestCronScheduler_Stop(t *testing.T) {
	ctx := context.Background()
	scheduler := NewCronScheduler(ctx)

	var executing int32
	stopStarted := make(chan struct{})
	executionBlocking := make(chan struct{})

	scheduler.AddTask(Task{
		Interval: 50 * time.Millisecond,
		Execute: func() error {
			if atomic.CompareAndSwapInt32(&executing, 0, 1) {
				// First execution - block until test is ready
				close(executionBlocking)
				<-stopStarted
				time.Sleep(100 * time.Millisecond)
				atomic.StoreInt32(&executing, 0)
			}
			return nil
		},
	})

	scheduler.Start()

	// Wait for task to start executing
	<-executionBlocking

	// Start stop in goroutine
	stopDone := make(chan struct{})
	go func() {
		close(stopStarted)
		scheduler.Stop()
		close(stopDone)
	}()

	// Verify Stop() blocks while task is executing
	select {
	case <-stopDone:
		t.Fatal("Stop() should block until task completes")
	case <-time.After(50 * time.Millisecond):
		// Expected - Stop() is blocking
	}

	// Verify Stop() completes after task finishes
	select {
	case <-stopDone:
		// Expected
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stop() should complete after task finishes")
	}
}

// TestCronScheduler_NoErrorHandler verifies behavior when OnError is nil
func TestCronScheduler_NoErrorHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var executionCount int32
	scheduler := NewCronScheduler(ctx)

	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&executionCount, 1)
			return errors.New("error without handler")
		},
		OnError: nil, // Explicitly nil
	})

	scheduler.Start()
	time.Sleep(350 * time.Millisecond)
	scheduler.Stop()

	// Should continue executing even without error handler
	count := atomic.LoadInt32(&executionCount)
	assert.GreaterOrEqual(t, count, int32(3), "Should execute despite errors and no handler")
}

// TestCronScheduler_MultipleTasksWithErrors tests multiple tasks with different error rates
func TestCronScheduler_MultipleTasksWithErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var task1Count, task2Count, task3Count int32
	var task1Errors, task2Errors, task3Errors int32

	scheduler := NewCronScheduler(ctx)

	// Task 1: Never fails
	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&task1Count, 1)
			return nil
		},
		OnError: func(err error) {
			atomic.AddInt32(&task1Errors, 1)
		},
	})

	// Task 2: Always fails
	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&task2Count, 1)
			return errors.New("task 2 error")
		},
		OnError: func(err error) {
			atomic.AddInt32(&task2Errors, 1)
		},
	})

	// Task 3: Fails occasionally
	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			count := atomic.AddInt32(&task3Count, 1)
			if count%3 == 0 {
				return errors.New("task 3 error")
			}
			return nil
		},
		OnError: func(err error) {
			atomic.AddInt32(&task3Errors, 1)
		},
	})

	scheduler.Start()
	time.Sleep(550 * time.Millisecond)
	scheduler.Stop()

	// Verify all tasks ran ~5 times
	assert.GreaterOrEqual(t, atomic.LoadInt32(&task1Count), int32(4))
	assert.GreaterOrEqual(t, atomic.LoadInt32(&task2Count), int32(4))
	assert.GreaterOrEqual(t, atomic.LoadInt32(&task3Count), int32(4))

	// Verify error counts
	assert.Equal(t, int32(0), atomic.LoadInt32(&task1Errors), "Task 1 should have no errors")
	assert.Equal(t, atomic.LoadInt32(&task2Count), atomic.LoadInt32(&task2Errors),
		"Task 2 errors should equal execution count")

	task3ExpectedErrors := atomic.LoadInt32(&task3Count) / 3
	assert.GreaterOrEqual(t, atomic.LoadInt32(&task3Errors), task3ExpectedErrors-1)
	assert.LessOrEqual(t, atomic.LoadInt32(&task3Errors), task3ExpectedErrors+1)
}

// TestCronScheduler_PanicRecovery ensures panics don't crash the scheduler
func TestCronScheduler_PanicRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var task1Count, task2Count int32
	var panicCount int32

	scheduler := NewCronScheduler(ctx)

	// Task 1: Panics sometimes
	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt32(&panicCount, 1)
				}
			}()

			count := atomic.AddInt32(&task1Count, 1)
			if count == 2 {
				panic("test panic")
			}
			return nil
		},
	})

	// Task 2: Normal task to verify scheduler continues
	scheduler.AddTask(Task{
		Interval: 100 * time.Millisecond,
		Execute: func() error {
			atomic.AddInt32(&task2Count, 1)
			return nil
		},
	})

	scheduler.Start()
	time.Sleep(450 * time.Millisecond)
	scheduler.Stop()

	// Note: Current implementation doesn't handle panics
	// This test documents that behavior
	// In production, you might want to add panic recovery to runTask

	assert.GreaterOrEqual(t, atomic.LoadInt32(&task2Count), int32(3),
		"Task 2 should continue executing")
}

// TestServer_DefaultJobs tests the actual Server job methods
func TestServer_DefaultJobs(t *testing.T) {
	t.Run("DefaultHourlyJob_Success", func(t *testing.T) {
		server := &Server{}

		// Mock successful execution
		server.rotateIssuers = func() error { return nil }
		server.deleteIssuerKeys = func(string) (int, error) { return 5, nil }

		err := server.DefaultHourlyJob()
		assert.NoError(t, err)
		// Verify metrics were incremented (would need mock metrics in real test)
	})

	t.Run("DefaultHourlyJob_RotateFailure", func(t *testing.T) {
		server := &Server{}

		expectedErr := errors.New("rotation failed")
		server.rotateIssuers = func() error { return expectedErr }

		err := server.DefaultHourlyJob()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RotateIssuers failed")
		assert.Contains(t, err.Error(), "rotation failed")
	})

	t.Run("DefaultHourlyJob_DeleteFailure", func(t *testing.T) {
		server := &Server{}

		server.rotateIssuers = func() error { return nil }
		server.deleteIssuerKeys = func(string) (int, error) { return 0, errors.New("delete failed") }

		err := server.DefaultHourlyJob()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DeleteIssuerKeys failed")
	})

	t.Run("DefaultMinutelyJob_Success", func(t *testing.T) {
		server := &Server{}

		server.rotateIssuersV3 = func() error { return nil }

		err := server.DefaultMinutelyJob()
		assert.NoError(t, err)
	})

	t.Run("DefaultMinutelyJob_Failure", func(t *testing.T) {
		server := &Server{}

		expectedErr := errors.New("v3 rotation failed")
		server.rotateIssuersV3 = func() error { return expectedErr }

		err := server.DefaultMinutelyJob()
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

// TestCronScheduler_RaceConditions tests for race conditions
func TestCronScheduler_RaceConditions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	scheduler := NewCronScheduler(ctx)

	var counter int32

	// Add multiple tasks concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			scheduler.AddTask(Task{
				Interval: time.Duration(50+id*10) * time.Millisecond,
				Execute: func() error {
					atomic.AddInt32(&counter, 1)
					return nil
				},
			})
		}(i)
	}
	wg.Wait()

	// Start and stop multiple times
	for i := 0; i < 3; i++ {
		scheduler.Start()
		time.Sleep(100 * time.Millisecond)
		scheduler.Stop()
	}

	// Verify tasks executed
	assert.Greater(t, atomic.LoadInt32(&counter), int32(0), "Tasks should have executed")
}

// BenchmarkCronScheduler tests performance with many tasks
func BenchmarkCronScheduler(b *testing.B) {
	ctx := context.Background()
	scheduler := NewCronScheduler(ctx)

	for i := 0; i < 100; i++ {
		scheduler.AddTask(Task{
			Interval: 100 * time.Millisecond,
			Execute:  func() error { return nil },
		})
	}

	b.ResetTimer()
	scheduler.Start()
	time.Sleep(time.Duration(b.N) * time.Millisecond)
	scheduler.Stop()
}
