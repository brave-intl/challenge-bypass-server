package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// IssuerManager defines the interface for issuer operations
type IssuerManager interface {
	RotateIssuers() error
	RotateIssuersV3() error
	DeleteIssuerKeys(duration string) (int64, error)
}

type CronScheduler struct {
	tasks   []Task
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	manager IssuerManager
}

type Task struct {
	Interval time.Duration
	Execute  func(IssuerManager) error
}

// NewCronScheduler creates a new scheduler
func NewCronScheduler(ctx context.Context, im IssuerManager) *CronScheduler {
	ctx, cancel := context.WithCancel(ctx)
	return &CronScheduler{
		ctx:     ctx,
		cancel:  cancel,
		manager: im,
	}
}

// AddTask adds a task to the scheduler
func (s *CronScheduler) AddTask(task Task) {
	s.tasks = append(s.tasks, task)
}

// Start begins executing all tasks (non-blocking)
func (s *CronScheduler) Start() {
	for _, task := range s.tasks {
		s.wg.Add(1)
		go s.runTask(task)
	}
}

// Stop gracefully stops all tasks
func (cs *CronScheduler) Stop() {
	cs.cancel()
	cs.wg.Wait()
}

func (cs *CronScheduler) runTask(task Task) {
	defer cs.wg.Done()

	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task.Execute(cs.manager); err != nil {
				// @TODO: Alert here
				fmt.Printf("Task execution failed: %v\n", err)
			}
		case <-cs.ctx.Done():
			return
		}
	}
}

func defaultHourlyJob(im IssuerManager) error {
	if err := im.RotateIssuers(); err != nil {
		cronTotal.WithLabelValues("hourlyRotationFailure").Inc()
		return fmt.Errorf("RotateIssuers failed: %w", err)
	}
	_, err := im.DeleteIssuerKeys("P1M")
	if err != nil {
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

// SetupCronJobs creates and starts the cron scheduler with default jobs
func (s *Server) SetupCronJobs(ctx context.Context) *CronScheduler {
	scheduler := NewCronScheduler(ctx, s)

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

	scheduler.Start()
	return scheduler
}
