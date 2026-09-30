package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// IssuerManager defines the interface for issuer operations. For now, this interface
// is specific to cron jobs.
type IssuerManager interface {
	RotateIssuers() error
	RotateIssuersV3() error
	DeleteIssuerKeys(duration string) (int64, error)
}

// CronScheduler collects the components needed to execute cron tasks.
type CronScheduler struct {
	tasks   []Task
	wg      sync.WaitGroup
	manager IssuerManager
}

// Task is a job that will run at an interval.
type Task struct {
	Interval time.Duration
	Execute  func(IssuerManager) error
}

// AddTask adds a task to the scheduler
func (cs *CronScheduler) AddTask(task Task) {
	cs.tasks = append(cs.tasks, task)
}

// Start begins executing all tasks (non-blocking)
func (cs *CronScheduler) Start(ctx context.Context) {
	for _, task := range cs.tasks {
		cs.wg.Add(1)
		go cs.runTask(ctx, task)
	}
}

func (cs *CronScheduler) runTask(ctx context.Context, task Task) {
	defer cs.wg.Done()

	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task.Execute(cs.manager); err != nil {
				// @TODO: Alert here once alert is merged
				fmt.Printf("Task execution failed: %v\n", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func defaultHourlyJob(im IssuerManager) error {
	if err := im.RotateIssuers(); err != nil {
		cronTotal.WithLabelValues("hourlyRotationFailure").Inc()
		return fmt.Errorf("RotateIssuers failed: %w", err)
	}
	if _, err := im.DeleteIssuerKeys("P1M"); err != nil {
		cronTotal.WithLabelValues("hourlyRotationPartialFailure").Inc()
		return fmt.Errorf("DeleteIssuerKeys failed: %w", err)
	}
	cronTotal.WithLabelValues("hourlyRotationSuccess").Inc()
	return nil
}

func defaultMinutelyJob(im IssuerManager) error {
	if err := im.RotateIssuersV3(); err != nil {
		cronTotal.WithLabelValues("minutelyRotationFailure").Inc()
		return err
	}
	cronTotal.WithLabelValues("minutelyRotationSuccess").Inc()
	return nil
}

// StartCronJobs creates and starts the cron scheduler with default jobs
func (s *Server) StartCronJobs(ctx context.Context) {
	scheduler := &CronScheduler{
		manager: s,
	}

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
