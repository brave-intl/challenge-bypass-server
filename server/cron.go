package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type CronScheduler struct {
	tasks  []Task
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

type Task struct {
	Interval time.Duration
	Execute  func() error
	OnError  func(error)
}

// NewCronScheduler creates a new scheduler
func NewCronScheduler(ctx context.Context) *CronScheduler {
	ctx, cancel := context.WithCancel(ctx)
	return &CronScheduler{
		ctx:    ctx,
		cancel: cancel,
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
func (s *CronScheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *CronScheduler) runTask(task Task) {
	defer s.wg.Done()

	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task.Execute(); err != nil {
				s.handleError(task, err)
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *CronScheduler) handleError(task Task, err error) {
	if task.OnError != nil {
		task.OnError(fmt.Errorf("task %s: %w", task.Interval, err))
	}
}

// DefaultHourlyJob rotates v2 issuers and deletes unneeded keys
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

// DefaultMinutelyJob roates v3 issuers
func (s *Server) DefaultMinutelyJob() error {
	if err := s.rotateIssuersV3(); err != nil {
		cronTotal.WithLabelValues("minutelyRotationFailure").Inc()
		return err
	}
	cronTotal.WithLabelValues("minutelyRotationSuccess").Inc()
	return nil
}
