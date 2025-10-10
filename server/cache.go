package server

import (
	"sync"
	"time"
)

// Configuration types
type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

// Cache interface
type CacheInterface interface {
	Get(k string) (any, bool)
	Delete(k string)
	SetDefault(k string, x any)
}

// SimpleCache implementation
type SimpleCache struct {
	items             sync.Map
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
	stopCleanup       chan bool
}

type cacheItem struct {
	value      any
	expiration int64 // Unix timestamp for expiration
}

// NewSimpleCache creates a new cache with the given default expiration and cleanup interval
func NewSimpleCache(defaultExpiration, cleanupInterval time.Duration) *SimpleCache {
	cache := &SimpleCache{
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
		stopCleanup:       make(chan bool),
	}
	// Start cleanup routine if cleanup interval > 0
	if cleanupInterval > 0 {
		go cache.startCleanupTimer()
	}
	return cache
}

// startCleanupTimer starts a timer that periodically cleans up expired items
func (c *SimpleCache) startCleanupTimer() {
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

// deleteExpired deletes expired items from the cache
func (c *SimpleCache) deleteExpired() {
	now := time.Now().UnixNano()
	c.items.Range(func(key, value any) bool {
		item, ok := value.(cacheItem)
		if ok && item.expiration > 0 && item.expiration < now {
			c.items.Delete(key)
		}
		return true
	})
}

// Get retrieves an item from the cache
func (c *SimpleCache) Get(k string) (any, bool) {
	value, found := c.items.Load(k)
	if !found {
		return nil, false
	}
	item, ok := value.(cacheItem)
	if !ok {
		return nil, false
	}
	// Check if item has expired
	if item.expiration > 0 && item.expiration < time.Now().UnixNano() {
		c.items.Delete(k)
		return nil, false
	}
	return item.value, true
}

// Delete removes an item from the cache
func (c *SimpleCache) Delete(k string) {
	c.items.Delete(k)
}

// SetDefault adds an item to the cache with the default expiration time
func (c *SimpleCache) SetDefault(k string, x any) {
	var expiration int64 = 0
	if c.defaultExpiration > 0 {
		expiration = time.Now().Add(c.defaultExpiration).UnixNano()
	}
	c.items.Store(k, cacheItem{
		value:      x,
		expiration: expiration,
	})
}

// Close stops the cleanup timer
func (c *SimpleCache) Close() {
	close(c.stopCleanup)
}

// retrieveFromCache safely retrieves a value from a named cache
func retrieveFromCache(
	caches map[string]CacheInterface,
	cacheName string,
	key string,
) any {
	if caches != nil {
		if cache, exists := caches[cacheName]; exists {
			if cached, found := cache.Get(key); found {
				return cached
			}
		}
	}
	return nil
}

// bootstrapCache creates all the caches
func bootstrapCache(cfg DBConfig) map[string]CacheInterface {
	if !cfg.CachingConfig.Enabled {
		return nil
	}

	caches := make(map[string]CacheInterface)
	defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
	cleanupInterval := defaultDuration * 2

	caches["issuers"] = NewSimpleCache(defaultDuration, cleanupInterval)
	caches["issuer"] = NewSimpleCache(defaultDuration, cleanupInterval)
	caches["redemptions"] = NewSimpleCache(defaultDuration, cleanupInterval)
	caches["issuercohort"] = NewSimpleCache(defaultDuration, cleanupInterval)

	return caches
}
