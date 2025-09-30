package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Task struct {
	Interval time.Duration
	Execute  func() error
}

// SetupCronTasks runs scheduled tasks and monitors for errors
func SetupCronTasks(ctx context.Context, now time.Time, tasks []Task) error {
	errChan := make(chan error, len(tasks))
	var wg sync.WaitGroup

	for _, task := range tasks {
		wg.Add(1)
		go runTask(ctx, &wg, task, now, errChan)
	}

	// Monitor goroutines and handle cleanup
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Wait for either an error from a goroutine or context cancellation
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func initialWait(now time.Time) time.Duration {
	nextMinute := time.Date(
		now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute()+1, 0, 0,
		now.Location(),
	)
	return nextMinute.Sub(now)
}

// runTask executes a scheduled task on the specified interval
func runTask(
	ctx context.Context,
	wg *sync.WaitGroup,
	task Task,
	now time.Time,
	errChan chan<- error,
) {
	defer wg.Done()

	// Wait until the first scheduled run
	initialWait := initialWait(now)

	select {
	case <-time.After(initialWait):
		// Continue to first execution
	case <-ctx.Done():
		return
	}

	// First execution
	if err := task.Execute(); err != nil {
		errChan <- fmt.Errorf("%s task error: %w", task.Interval, err)
		return
	}

	// Setup ticker for subsequent executions
	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task.Execute(); err != nil {
				errChan <- fmt.Errorf("%s task error: %w", task.Interval, err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) DefaultHourlyJob() error {
	if err := s.rotateIssuers(); err != nil {
		cronTotal.WithLabelValues("hourlyRotationFailure").Inc()
		return fmt.Errorf("RotateIssuers failed: %w", err)
	}

	_, err := s.deleteIssuerKeys("P1M")
	if err != nil {
		cronTotal.WithLabelValues("hourlyRotationPartialFailure").Inc()
		return fmt.Errorf("DeleteIssuerKeys failed: %w", err)
	}

	cronTotal.WithLabelValues("hourlyRotationSuccess").Inc()
	return nil
}

func (s *Server) DefaultMinutelyJob() error {
	if err := s.rotateIssuersV3(); err != nil {
		cronTotal.WithLabelValues("minutelyRotationFailure").Inc()
		return err
	}
	cronTotal.WithLabelValues("minutelyRotationSuccess").Inc()
	return nil
}
