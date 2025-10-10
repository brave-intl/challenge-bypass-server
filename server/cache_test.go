package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	A int
	B string
}

func TestSetGetDelete(t *testing.T) {
	cache := NewSimpleCache(5*time.Second, 0)
	key := "testkey"
	val := "testval"

	cache.SetDefault(key, val)
	got, found := cache.Get(key)
	require.True(t, found, "Expected key %q to be present after SetDefault", key)
	assert.Equal(t, val, got, "Expected value for key %q", key)

	cache.Delete(key)
	_, found = cache.Get(key)
	assert.False(t, found, "Expected key %q to be deleted", key)
}

func TestExpiration(t *testing.T) {
	cache := NewSimpleCache(50*time.Millisecond, 0)
	key := "expirekey"
	val := 42
	cache.SetDefault(key, val)

	got, found := cache.Get(key)
	require.True(t, found, "Expected to get key before expiration")
	assert.Equal(t, val, got, "Expected to get correct value before expiration")

	time.Sleep(80 * time.Millisecond)
	_, found = cache.Get(key)
	assert.False(t, found, "Expected key to be expired after expiration time")
}

func TestNoExpiration(t *testing.T) {
	cache := NewSimpleCache(0, 0)
	key := "nokey"
	cache.SetDefault(key, "persist")
	time.Sleep(30 * time.Millisecond)
	val, found := cache.Get(key)
	require.True(t, found, "Expected key to persist with no expiration")
	assert.Equal(t, "persist", val, "Expected persisted value")
}

func TestCleanupRoutine(t *testing.T) {
	cache := NewSimpleCache(20*time.Millisecond, 20*time.Millisecond)
	key := "c"
	cache.SetDefault(key, "bye")
	time.Sleep(80 * time.Millisecond)
	_, found := cache.Get(key)
	assert.False(t, found, "Item was not cleaned by cleanup goroutine")
}

func TestMultipleTypes(t *testing.T) {
	cache := NewSimpleCache(0, 0)
	cache.SetDefault("str", "hello")
	cache.SetDefault("int", 123)
	cache.SetDefault("struct", testStruct{A: 9, B: "b"})

	val, found := cache.Get("str")
	require.True(t, found, "String key not found")
	assert.Equal(t, "hello", val, "String value not retrieved properly")

	val, found = cache.Get("int")
	require.True(t, found, "Int key not found")
	assert.Equal(t, 123, val, "Int value not retrieved properly")

	val, found = cache.Get("struct")
	require.True(t, found, "Struct value not found")
	assert.True(t, reflect.DeepEqual(testStruct{A: 9, B: "b"}, val), "Struct value mismatch")
}

func TestRetrieveFromCacheFound(t *testing.T) {
	cache := NewSimpleCache(5*time.Second, 0)
	cache.SetDefault("key", 100)
	caches := map[string]CacheInterface{"mycache": cache}
	res := retrieveFromCache(caches, "mycache", "key")
	assert.Equal(t, 100, res, "Expected retrieved value from cache")
}

func TestRetrieveFromCacheNotFound(t *testing.T) {
	cache := NewSimpleCache(5*time.Second, 0)
	caches := map[string]CacheInterface{"mycache": cache}
	res := retrieveFromCache(caches, "mycache", "missing")
	assert.Nil(t, res, "Expected nil for missing key")
}

func TestRetrieveFromCacheNilCaches(t *testing.T) {
	res := retrieveFromCache(nil, "any", "any")
	assert.Nil(t, res, "Expected nil when caches is nil")
}

func TestBootstrapCacheCreatesMap(t *testing.T) {
	cfg := DBConfig{
		CachingConfig: CachingConfig{
			Enabled:       true,
			ExpirationSec: 2,
		},
	}
	caches := bootstrapCache(cfg)
	wantKeys := []string{"issuers", "issuer", "redemptions", "issuercohort"}
	for _, k := range wantKeys {
		_, ok := caches[k]
		assert.True(t, ok, "Expected key %q in bootstrapped cache", k)
	}
}

func TestBootstrapCacheSetsExpiration(t *testing.T) {
	cfg := DBConfig{
		CachingConfig: CachingConfig{
			Enabled:       true,
			ExpirationSec: 1,
		},
	}
	caches := bootstrapCache(cfg)
	cache := caches["issuers"].(*SimpleCache)
	assert.Equal(t, 1*time.Second, cache.defaultExpiration, "Expected defaultExpiration 1s")
	assert.Equal(t, 2*time.Second, cache.cleanupInterval, "Expected cleanupInterval 2s")
}
