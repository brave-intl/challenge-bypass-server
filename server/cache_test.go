package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleCache_SetDefault(t *testing.T) {
	type testStruct struct {
		A int
		B string
	}

	tests := []struct {
		name              string
		defaultExpiration time.Duration
		key               string
		value             any
		wantStored        bool
	}{
		{
			name:              "set_string_value",
			defaultExpiration: 5 * time.Second,
			key:               "testkey",
			value:             "testval",
			wantStored:        true,
		},
		{
			name:              "set_int_value",
			defaultExpiration: 0,
			key:               "intkey",
			value:             123,
			wantStored:        true,
		},
		{
			name:              "set_struct_value",
			defaultExpiration: 0,
			key:               "structkey",
			value:             testStruct{A: 9, B: "b"},
			wantStored:        true,
		},
		{
			name:              "set_with_no_expiration",
			defaultExpiration: 0,
			key:               "noexpire",
			value:             "persist",
			wantStored:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewSimpleCache(tt.defaultExpiration, 0)
			cache.SetDefault(tt.key, tt.value)

			// Verify it was stored
			got, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantStored, found, "Expected key to be stored")
			if found {
				assert.Equal(t, tt.value, got, "Expected correct value stored")
			}
		})
	}
}

func TestSimpleCache_Get(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		setupKey          string
		setupValue        any
		getKey            string
		wantValue         any
		wantFound         bool
	}{
		{
			name:              "get_existing_key",
			defaultExpiration: 5 * time.Second,
			setupKey:          "testkey",
			setupValue:        "testval",
			getKey:            "testkey",
			wantValue:         "testval",
			wantFound:         true,
		},
		{
			name:              "get_nonexistent_key",
			defaultExpiration: 5 * time.Second,
			setupKey:          "testkey",
			setupValue:        "testval",
			getKey:            "wrongkey",
			wantValue:         nil,
			wantFound:         false,
		},
		{
			name:              "get_before_expiration",
			defaultExpiration: 50 * time.Millisecond,
			setupKey:          "expirekey",
			setupValue:        42,
			getKey:            "expirekey",
			wantValue:         42,
			wantFound:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewSimpleCache(tt.defaultExpiration, 0)
			cache.SetDefault(tt.setupKey, tt.setupValue)

			got, found := cache.Get(tt.getKey)
			assert.Equal(t, tt.wantFound, found, "Expected found status")
			assert.Equal(t, tt.wantValue, got, "Expected correct value")
		})
	}
}

func TestSimpleCache_Get_Expiration(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		key               string
		value             any
		sleepDuration     time.Duration
		wantFound         bool
	}{
		{
			name:              "expired_item_not_found",
			defaultExpiration: 50 * time.Millisecond,
			key:               "expirekey",
			value:             42,
			sleepDuration:     80 * time.Millisecond,
			wantFound:         false,
		},
		{
			name:              "no_expiration_persists",
			defaultExpiration: 0,
			key:               "nokey",
			value:             "persist",
			sleepDuration:     30 * time.Millisecond,
			wantFound:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewSimpleCache(tt.defaultExpiration, 0)
			cache.SetDefault(tt.key, tt.value)

			time.Sleep(tt.sleepDuration)

			_, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantFound, found, "Expected expiration behavior")
		})
	}
}

func TestSimpleCache_Delete(t *testing.T) {
	tests := []struct {
		name       string
		setupKey   string
		setupValue any
		deleteKey  string
		wantFound  bool
	}{
		{
			name:       "delete_existing_key",
			setupKey:   "testkey",
			setupValue: "testval",
			deleteKey:  "testkey",
			wantFound:  false,
		},
		{
			name:       "delete_nonexistent_key",
			setupKey:   "testkey",
			setupValue: "testval",
			deleteKey:  "wrongkey",
			wantFound:  true, // original key should still exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewSimpleCache(5*time.Second, 0)
			cache.SetDefault(tt.setupKey, tt.setupValue)
			cache.Delete(tt.deleteKey)

			_, found := cache.Get(tt.setupKey)
			assert.Equal(t, tt.wantFound, found, "Expected key presence after delete")
		})
	}
}

func TestSimpleCache_CleanupRoutine(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		cleanupInterval   time.Duration
		key               string
		value             any
		sleepDuration     time.Duration
		wantFound         bool
	}{
		{
			name:              "cleanup_removes_expired_items",
			defaultExpiration: 20 * time.Millisecond,
			cleanupInterval:   20 * time.Millisecond,
			key:               "c",
			value:             "bye",
			sleepDuration:     80 * time.Millisecond,
			wantFound:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewSimpleCache(tt.defaultExpiration, tt.cleanupInterval)
			cache.SetDefault(tt.key, tt.value)

			time.Sleep(tt.sleepDuration)

			_, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantFound, found, "Expected cleanup to remove expired item")

			cache.Close() // Clean up goroutine
		})
	}
}

func TestSimpleCache_MultipleTypes(t *testing.T) {
	type testStruct struct {
		A int
		B string
	}

	tests := []struct {
		name      string
		key       string
		value     any
		wantValue any
	}{
		{
			name:      "store_string",
			key:       "str",
			value:     "hello",
			wantValue: "hello",
		},
		{
			name:      "store_int",
			key:       "int",
			value:     123,
			wantValue: 123,
		},
		{
			name:      "store_struct",
			key:       "struct",
			value:     testStruct{A: 9, B: "b"},
			wantValue: testStruct{A: 9, B: "b"},
		},
	}

	cache := NewSimpleCache(0, 0)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.SetDefault(tt.key, tt.value)

			val, found := cache.Get(tt.key)
			require.True(t, found, "Expected key to be found")
			assert.True(t, reflect.DeepEqual(tt.wantValue, val), "Expected correct value")
		})
	}
}

func TestRetrieveFromCache(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() map[string]Cache
		cacheName string
		key       string
		wantValue any
		wantFound bool
	}{
		{
			name: "retrieve_existing_value",
			setupFunc: func() map[string]Cache {
				cache := NewSimpleCache(5*time.Second, 0)
				cache.SetDefault("key", 100)
				return map[string]Cache{"mycache": cache}
			},
			cacheName: "mycache",
			key:       "key",
			wantValue: 100,
			wantFound: true,
		},
		{
			name: "retrieve_missing_key",
			setupFunc: func() map[string]Cache {
				cache := NewSimpleCache(5*time.Second, 0)
				return map[string]Cache{"mycache": cache}
			},
			cacheName: "mycache",
			key:       "missing",
			wantValue: nil,
			wantFound: false,
		},
		{
			name: "retrieve_missing_cache",
			setupFunc: func() map[string]Cache {
				cache := NewSimpleCache(5*time.Second, 0)
				return map[string]Cache{"mycache": cache}
			},
			cacheName: "wrongcache",
			key:       "key",
			wantValue: nil,
			wantFound: false,
		},
		{
			name: "retrieve_nil_caches",
			setupFunc: func() map[string]Cache {
				return nil
			},
			cacheName: "any",
			key:       "any",
			wantValue: nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caches := tt.setupFunc()

			res, ok := retrieveFromCache[any](caches, tt.cacheName, tt.key)
			assert.Equal(t, tt.wantFound, ok, "Expected found status")
			assert.Equal(t, tt.wantValue, res, "Expected correct value")
		})
	}
}

func TestRetrieveFromCache_TypedRetrieval(t *testing.T) {
	cache := NewSimpleCache(5*time.Second, 0)
	cache.SetDefault("key", 100)
	caches := map[string]Cache{"mycache": cache}

	res, ok := retrieveFromCache[int](caches, "mycache", "key")
	assert.True(t, ok, "Expected to find value in cache")
	assert.Equal(t, 100, res, "Expected retrieved value from cache")
}

func TestBootstrapCache(t *testing.T) {
	tests := []struct {
		name           string
		config         DBConfig
		wantCacheKeys  []string
		wantExpiration time.Duration
		wantCleanup    time.Duration
		wantNil        bool
	}{
		{
			name: "creates_all_caches",
			config: DBConfig{
				CachingConfig: CachingConfig{
					Enabled:       true,
					ExpirationSec: 2,
				},
			},
			wantCacheKeys:  []string{"issuers", "issuer", "redemptions", "issuercohort"},
			wantExpiration: 2 * time.Second,
			wantCleanup:    4 * time.Second,
			wantNil:        false,
		},
		{
			name: "sets_correct_expiration",
			config: DBConfig{
				CachingConfig: CachingConfig{
					Enabled:       true,
					ExpirationSec: 1,
				},
			},
			wantCacheKeys:  []string{"issuers", "issuer", "redemptions", "issuercohort"},
			wantExpiration: 1 * time.Second,
			wantCleanup:    2 * time.Second,
			wantNil:        false,
		},
		{
			name: "disabled_returns_nil",
			config: DBConfig{
				CachingConfig: CachingConfig{
					Enabled:       false,
					ExpirationSec: 2,
				},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caches := bootstrapCache(tt.config)

			if tt.wantNil {
				assert.Nil(t, caches, "Expected nil caches when disabled")
				return
			}

			require.NotNil(t, caches, "Expected non-nil caches")

			for _, key := range tt.wantCacheKeys {
				cache, ok := caches[key]
				assert.True(t, ok, "Expected key %q in bootstrapped cache", key)

				if simpleCache, ok := cache.(*SimpleCache); ok {
					assert.Equal(t, tt.wantExpiration, simpleCache.defaultExpiration,
						"Expected defaultExpiration %v for cache %q", tt.wantExpiration, key)
					assert.Equal(t, tt.wantCleanup, simpleCache.cleanupInterval,
						"Expected cleanupInterval %v for cache %q", tt.wantCleanup, key)
				}
			}
		})
	}
}
