package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock for IssuerManager
type MockIssuerManager struct {
	mock.Mock
}

func (m *MockIssuerManager) RotateIssuers() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockIssuerManager) RotateIssuersV3() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockIssuerManager) DeleteIssuerKeys(duration string) (int64, error) {
	args := m.Called(duration)
	return args.Get(0).(int64), args.Error(1)
}

// Initialize metrics for testing
func init() {
	cronTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cron_jobs_total",
			Help: "Total number of cron job executions",
		},
		[]string{"status"},
	)
	prometheus.MustRegister(cronTotal)
}

func TestCronScheduler_AddTask(t *testing.T) {
	mockManager := &MockIssuerManager{}
	scheduler := CronScheduler{manager: mockManager}

	task1 := Task{
		Interval: time.Second,
		Execute: func(im IssuerManager) error {
			return nil
		},
	}

	task2 := Task{
		Interval: time.Minute,
		Execute: func(im IssuerManager) error {
			return nil
		},
	}

	scheduler.AddTask(task1)
	assert.Len(t, scheduler.tasks, 1)

	scheduler.AddTask(task2)
	assert.Len(t, scheduler.tasks, 2)
}

func TestCronScheduler_Start(t *testing.T) {
	ctx := context.Background()
	mockManager := &MockIssuerManager{}
	scheduler := CronScheduler{manager: mockManager}

	var counter int32
	task := Task{
		Interval: 50 * time.Millisecond,
		Execute: func(im IssuerManager) error {
			atomic.AddInt32(&counter, 1)
			return nil
		},
	}

	scheduler.AddTask(task)
	scheduler.Start(ctx)

	// Wait for task to execute at least twice
	time.Sleep(150 * time.Millisecond)

	// Check that task was executed
	count := atomic.LoadInt32(&counter)
	assert.GreaterOrEqual(t, count, int32(2))
}

func TestCronScheduler_TaskExecutionError(t *testing.T) {
	ctx := context.Background()
	mockManager := &MockIssuerManager{}
	scheduler := CronScheduler{manager: mockManager}

	errorCount := 0
	var mu sync.Mutex

	task := Task{
		Interval: 50 * time.Millisecond,
		Execute: func(im IssuerManager) error {
			mu.Lock()
			errorCount++
			mu.Unlock()
			return errors.New("test error")
		},
	}

	scheduler.AddTask(task)
	scheduler.Start(ctx)

	// Wait for task to execute at least once
	time.Sleep(100 * time.Millisecond)

	// Verify error occurred but didn't stop the scheduler
	mu.Lock()
	assert.GreaterOrEqual(t, errorCount, 1)
	mu.Unlock()
}

func TestCronScheduler_MultipleTasksConcurrent(t *testing.T) {
	ctx := context.Background()
	mockManager := &MockIssuerManager{}
	scheduler := CronScheduler{manager: mockManager}

	var counter1, counter2 int32

	task1 := Task{
		Interval: 50 * time.Millisecond,
		Execute: func(im IssuerManager) error {
			atomic.AddInt32(&counter1, 1)
			return nil
		},
	}

	task2 := Task{
		Interval: 75 * time.Millisecond,
		Execute: func(im IssuerManager) error {
			atomic.AddInt32(&counter2, 1)
			return nil
		},
	}

	scheduler.AddTask(task1)
	scheduler.AddTask(task2)
	scheduler.Start(ctx)

	// Wait for tasks to execute
	time.Sleep(200 * time.Millisecond)

	// Verify both tasks executed
	assert.GreaterOrEqual(t, atomic.LoadInt32(&counter1), int32(3))
	assert.GreaterOrEqual(t, atomic.LoadInt32(&counter2), int32(2))
}

func TestDefaultHourlyJob_Success(t *testing.T) {
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuers").Return(nil)
	mockManager.On("DeleteIssuerKeys", "P1M").Return(int64(5), nil)

	// Reset metric
	cronTotal.Reset()

	err := defaultHourlyJob(mockManager)

	assert.NoError(t, err)
	mockManager.AssertExpectations(t)

	// Check metrics
	assert.Equal(t, float64(1), testutil.ToFloat64(cronTotal.WithLabelValues("hourlyRotationSuccess")))
}

func TestDefaultHourlyJob_RotateIssuersFailure(t *testing.T) {
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuers").Return(errors.New("rotation failed"))

	// Reset metric
	cronTotal.Reset()

	err := defaultHourlyJob(mockManager)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RotateIssuers failed")
	mockManager.AssertExpectations(t)

	// Check metrics
	assert.Equal(t, float64(1), testutil.ToFloat64(cronTotal.WithLabelValues("hourlyRotationFailure")))
}

func TestDefaultHourlyJob_DeleteIssuerKeysFailure(t *testing.T) {
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuers").Return(nil)
	mockManager.On("DeleteIssuerKeys", "P1M").Return(int64(0), errors.New("delete failed"))

	// Reset metric
	cronTotal.Reset()

	err := defaultHourlyJob(mockManager)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DeleteIssuerKeys failed")
	mockManager.AssertExpectations(t)

	// Check metrics
	assert.Equal(t, float64(1), testutil.ToFloat64(cronTotal.WithLabelValues("hourlyRotationPartialFailure")))
}

func TestDefaultMinutelyJob_Success(t *testing.T) {
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuersV3").Return(nil)

	// Reset metric
	cronTotal.Reset()

	err := defaultMinutelyJob(mockManager)

	assert.NoError(t, err)
	mockManager.AssertExpectations(t)

	// Check metrics
	assert.Equal(t, float64(1), testutil.ToFloat64(cronTotal.WithLabelValues("minutelyRotationSuccess")))
}

func TestDefaultMinutelyJob_Failure(t *testing.T) {
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuersV3").Return(errors.New("rotation v3 failed"))

	// Reset metric
	cronTotal.Reset()

	err := defaultMinutelyJob(mockManager)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rotation v3 failed")
	mockManager.AssertExpectations(t)

	// Check metrics
	assert.Equal(t, float64(1), testutil.ToFloat64(cronTotal.WithLabelValues("minutelyRotationFailure")))
}

// MockServer for testing SetupCronJobs
type MockServer struct {
	MockIssuerManager
}

func (s *MockServer) StartCronJobs(ctx context.Context) {
	scheduler := CronScheduler{manager: s}

	// Hourly job
	scheduler.AddTask(Task{
		Interval: time.Hour,
		Execute:  defaultHourlyJob,
	})

	// Minutely job
	scheduler.AddTask(Task{
		Interval: time.Minute,
		Execute:  defaultMinutelyJob,
	})

	scheduler.Start(ctx)
}

// Benchmark test
func BenchmarkCronScheduler_RunTask(b *testing.B) {
	ctx := context.Background()
	mockManager := &MockIssuerManager{}
	mockManager.On("RotateIssuers").Return(nil)
	mockManager.On("DeleteIssuerKeys", mock.Anything).Return(int64(5), nil)

	scheduler := CronScheduler{manager: mockManager}

	task := Task{
		Interval: time.Millisecond,
		Execute: func(im IssuerManager) error {
			return nil
		},
	}

	b.ResetTimer()
	for b.Loop() {
		scheduler.AddTask(task)
	}

	scheduler.Start(ctx)
	time.Sleep(10 * time.Millisecond)
}

// Test for context cancellation
func TestCronScheduler_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mockManager := &MockIssuerManager{}
	scheduler := CronScheduler{manager: mockManager}

	var executed int32
	task := Task{
		Interval: 50 * time.Millisecond,
		Execute: func(im IssuerManager) error {
			atomic.AddInt32(&executed, 1)
			return nil
		},
	}

	scheduler.AddTask(task)
	scheduler.Start(ctx)

	// Cancel context
	cancel()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Task should have stopped
	count := atomic.LoadInt32(&executed)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, count, atomic.LoadInt32(&executed))
}
