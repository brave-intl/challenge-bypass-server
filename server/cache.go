package server

import (
	"sync"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
)

type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

type Cache[T any] interface {
	Get(k string) (T, bool)
	Delete(k string)
	SetDefault(k string, x T)
}

// Clock interface allows us to mock time in tests
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

type SimpleCache[T any] struct {
	items             sync.Map
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
	stopCleanup       chan bool
	clock             Clock
}

type cacheItem[T any] struct {
	value      T
	expiration int64
}

// NewSimpleCache creates a new cache with the given default expiration and cleanup interval
func NewSimpleCache[T any](defaultExpiration, cleanupInterval time.Duration) *SimpleCache[T] {
	return newSimpleCacheWithClock[T](defaultExpiration, cleanupInterval, RealClock{})
}

func newSimpleCacheWithClock[T any](defaultExpiration, cleanupInterval time.Duration, clock Clock) *SimpleCache[T] {
	cache := &SimpleCache[T]{
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
		stopCleanup:       make(chan bool),
		clock:             clock,
	}

	if cleanupInterval > 0 {
		go cache.startCleanupTimer()
	}

	return cache
}

func (c *SimpleCache[T]) startCleanupTimer() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.deleteExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *SimpleCache[T]) deleteExpired() {
	now := c.clock.Now().UnixNano()
	c.items.Range(func(key, value any) bool {
		item, ok := value.(cacheItem[T])
		if ok && item.expiration > 0 && item.expiration < now {
			c.items.Delete(key)
		}
		return true
	})
}

func (c *SimpleCache[T]) Get(k string) (T, bool) {
	var zero T
	value, found := c.items.Load(k)
	if !found {
		return zero, false
	}

	item, ok := value.(cacheItem[T])
	if !ok {
		return zero, false
	}

	if item.expiration > 0 && item.expiration < c.clock.Now().UnixNano() {
		c.items.Delete(k)
		return zero, false
	}

	return item.value, true
}

// Delete removes an item from the cache
func (c *SimpleCache[T]) Delete(k string) {
	c.items.Delete(k)
}

// SetDefault adds an item to the cache with the default expiration time
func (c *SimpleCache[T]) SetDefault(k string, x T) {
	var expiration int64 = 0
	if c.defaultExpiration > 0 {
		expiration = c.clock.Now().Add(c.defaultExpiration).UnixNano()
	}

	c.items.Store(k, cacheItem[T]{
		value:      x,
		expiration: expiration,
	})
}

// Specialized cache types for type safety
type IssuerCache = *SimpleCache[*model.Issuer]
type IssuerListCache = *SimpleCache[[]model.Issuer]
type RedemptionCache = *SimpleCache[*Redemption]
type IssuerCohortCache = *SimpleCache[[]model.Issuer]

// CacheCollection holds all application caches with proper types
type CacheCollection struct {
	Issuer       IssuerCache
	Issuers      IssuerListCache
	Redemptions  RedemptionCache
	IssuerCohort IssuerCohortCache
}

// bootstrapCache creates all the caches with proper types
func bootstrapCache(cfg DBConfig) *CacheCollection {
	if !cfg.CachingConfig.Enabled {
		return nil
	}

	defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
	cleanupInterval := defaultDuration * 2

	return &CacheCollection{
		Issuer:       NewSimpleCache[*model.Issuer](defaultDuration, cleanupInterval),
		Issuers:      NewSimpleCache[[]model.Issuer](defaultDuration, cleanupInterval),
		Redemptions:  NewSimpleCache[*Redemption](defaultDuration, cleanupInterval),
		IssuerCohort: NewSimpleCache[[]model.Issuer](defaultDuration, cleanupInterval),
	}
}
