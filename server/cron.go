package server

import (
	"os"
	"time"
)

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	// Determine cadence duration
	cadence := 1 * time.Hour
	startMinute := 0
	if os.Getenv("ENV") == "production" {
		startMinute = 1
	}

	// Calculate time until the next hour at the specified minute
	now := time.Now()
	nextHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, startMinute, 0, 0, now.Location())
	if nextHour.Before(now) {
		nextHour = nextHour.Add(time.Hour)
	}
	timeUntilNextHour := nextHour.Sub(now)

	// Set up the hourly tasks
	go func() {
		// Wait until the next hour at the specified minute before starting the ticker
		time.Sleep(timeUntilNextHour)

		// Execute immediately after initial wait
		if err := c.rotateIssuers(); err != nil {
			panic(err)
		}

		rows, err := c.deleteIssuerKeys("P1M")
		if err != nil {
			panic(err)
		}
		c.Logger.Info("cron", "delete issuers keys removed", rows)

		// Create a ticker that fires every hour
		ticker := time.NewTicker(cadence)
		defer ticker.Stop()

		for range ticker.C {
			if err := c.rotateIssuers(); err != nil {
				panic(err)
			}

			rows, err := c.deleteIssuerKeys("P1M")
			if err != nil {
				panic(err)
			}
			c.Logger.Info("cron", "delete issuers keys removed", rows)
		}
	}()

	// Set up the minute task
	go func() {
		// Calculate time until the next minute
		now := time.Now()
		nextMinute := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, now.Location())
		timeUntilNextMinute := nextMinute.Sub(now)

		// Wait until the next minute before starting the ticker
		time.Sleep(timeUntilNextMinute)

		// Execute immediately after initial wait
		if err := c.rotateIssuersV3(); err != nil {
			panic(err)
		}

		// Create a ticker that fires every minute
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := c.rotateIssuersV3(); err != nil {
				panic(err)
			}
		}
	}()
}
