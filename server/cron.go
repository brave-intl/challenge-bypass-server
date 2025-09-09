package server

import (
	"os"
	"time"
)

// SetupCronTasks run two functions every hour
func (s *Server) SetupCronTasks() {
	s.ensureCronDefaults()

	cadence := 1 * time.Hour
	startMinute := 0
	if os.Getenv("ENV") == "production" {
		startMinute = 1
	}
	now := s.Now()
	nextHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, startMinute, 0, 0, now.Location())
	if nextHour.Before(now) {
		nextHour = nextHour.Add(time.Hour)
	}
	timeUntilNextHour := nextHour.Sub(now)

	go func() {
		s.Sleep(timeUntilNextHour)
		if err := s.RotateIssuers(); err != nil {
			panic(err)
		}
		rows, err := s.DeleteIssuerKeys("P1M")
		if err != nil {
			panic(err)
		}
		s.Logger.Info("cron", "delete issuers keys removed", rows)
		tickerC := s.NewTicker(cadence)
		for range tickerC {
			if err := s.RotateIssuers(); err != nil {
				panic(err)
			}
			rows, err := s.DeleteIssuerKeys("P1M")
			if err != nil {
				panic(err)
			}
			s.Logger.Info("cron", "delete issuers keys removed", rows)
		}
	}()

	go func() {
		now := s.Now()
		nextMinute := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, now.Location())
		timeUntilNextMinute := nextMinute.Sub(now)
		s.Sleep(timeUntilNextMinute)
		if err := s.RotateIssuersV3(); err != nil {
			panic(err)
		}
		tickerC := s.NewTicker(1 * time.Minute)
		for range tickerC {
			if err := s.RotateIssuersV3(); err != nil {
				panic(err)
			}
		}
	}()
}

func (s *Server) ensureCronDefaults() {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Sleep == nil {
		s.Sleep = time.Sleep
	}
	if s.NewTicker == nil {
		s.NewTicker = func(d time.Duration) <-chan time.Time {
			return time.NewTicker(d).C
		}
	}
	if s.RotateIssuers == nil {
		s.RotateIssuers = s.rotateIssuers
	}
	if s.DeleteIssuerKeys == nil {
		s.DeleteIssuerKeys = s.deleteIssuerKeys
	}
	if s.RotateIssuersV3 == nil {
		s.RotateIssuersV3 = s.rotateIssuersV3
	}
}
