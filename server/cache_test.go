package server

import (
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockClock struct {
	CurrentTime time.Time
}

func (m *MockClock) Now() time.Time {
	return m.CurrentTime
}

func (m *MockClock) Advance(d time.Duration) {
	m.CurrentTime = m.CurrentTime.Add(d)
}

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
		advanceDuration   time.Duration
		wantStored        bool
		wantValue         any
	}{
		{
			name:              "set_string_value",
			defaultExpiration: 5 * time.Second,
			key:               "stringkey",
			value:             "hello",
			advanceDuration:   0,
			wantStored:        true,
			wantValue:         "hello",
		},
		{
			name:              "set_int_value",
			defaultExpiration: 5 * time.Second,
			key:               "intkey",
			value:             123,
			advanceDuration:   0,
			wantStored:        true,
			wantValue:         123,
		},
		{
			name:              "set_struct_value",
			defaultExpiration: 5 * time.Second,
			key:               "structkey",
			value:             testStruct{A: 9, B: "b"},
			advanceDuration:   0,
			wantStored:        true,
			wantValue:         testStruct{A: 9, B: "b"},
		},
		{
			name:              "set_with_no_expiration",
			defaultExpiration: 0,
			key:               "noexpire",
			value:             "persist",
			advanceDuration:   0,
			wantStored:        true,
			wantValue:         "persist",
		},
		{
			name:              "no_expiration_persists_after_time",
			defaultExpiration: 0,
			key:               "nokey",
			value:             99,
			advanceDuration:   30 * time.Millisecond,
			wantStored:        true,
			wantValue:         99,
		},
		{
			name:              "item_available_before_expiration",
			defaultExpiration: 5 * time.Second,
			key:               "expirekey",
			value:             "value",
			advanceDuration:   3 * time.Second,
			wantStored:        true,
			wantValue:         "value",
		},
		{
			name:              "item_expired_after_expiration",
			defaultExpiration: 5 * time.Second,
			key:               "expirekey",
			value:             "value",
			advanceDuration:   6 * time.Second,
			wantStored:        false,
			wantValue:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}

			switch v := tt.value.(type) {
			case string:
				cache := newSimpleCacheWithClock[string](tt.defaultExpiration, 0, mockClock)
				cache.SetDefault(tt.key, v)
				if tt.advanceDuration > 0 {
					mockClock.Advance(tt.advanceDuration)
				}
				got, found := cache.Get(tt.key)
				assert.Equal(t, tt.wantStored, found, "Expected key storage status")
				if found {
					assert.Equal(t, tt.wantValue, got, "Expected correct value stored")
				}
			case int:
				cache := newSimpleCacheWithClock[int](tt.defaultExpiration, 0, mockClock)
				cache.SetDefault(tt.key, v)
				if tt.advanceDuration > 0 {
					mockClock.Advance(tt.advanceDuration)
				}
				got, found := cache.Get(tt.key)
				assert.Equal(t, tt.wantStored, found, "Expected key storage status")
				if found {
					assert.Equal(t, tt.wantValue, got, "Expected correct value stored")
				}
			case testStruct:
				cache := newSimpleCacheWithClock[testStruct](tt.defaultExpiration, 0, mockClock)
				cache.SetDefault(tt.key, v)
				if tt.advanceDuration > 0 {
					mockClock.Advance(tt.advanceDuration)
				}
				got, found := cache.Get(tt.key)
				assert.Equal(t, tt.wantStored, found, "Expected key storage status")
				if found {
					assert.Equal(t, tt.wantValue, got, "Expected correct value stored")
				}
			}
		})
	}
}

func TestSimpleCache_Get(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		setupKey          string
		setupValue        string
		getKey            string
		wantValue         string
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
			wantValue:         "",
			wantFound:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
			cache := newSimpleCacheWithClock[string](tt.defaultExpiration, 0, mockClock)
			cache.SetDefault(tt.setupKey, tt.setupValue)

			got, found := cache.Get(tt.getKey)

			assert.Equal(t, tt.wantFound, found, "Expected found status")
			assert.Equal(t, tt.wantValue, got, "Expected correct value")
		})
	}
}

func TestSimpleCache_Delete(t *testing.T) {
	tests := []struct {
		name       string
		setupKey   string
		setupValue string
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
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
			cache := newSimpleCacheWithClock[string](5*time.Second, 0, mockClock)
			cache.SetDefault(tt.setupKey, tt.setupValue)

			cache.Delete(tt.deleteKey)

			_, found := cache.Get(tt.setupKey)
			assert.Equal(t, tt.wantFound, found, "Expected key presence after delete")
		})
	}
}

func TestSimpleCache_DeleteExpired(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		keys              []string
		values            []string
		advanceDuration   time.Duration
		wantFound         []bool
	}{
		{
			name:              "removes_all_expired_items",
			defaultExpiration: 5 * time.Second,
			keys:              []string{"key1", "key2", "key3"},
			values:            []string{"value1", "value2", "value3"},
			advanceDuration:   6 * time.Second,
			wantFound:         []bool{false, false, false},
		},
		{
			name:              "keeps_non_expired_items",
			defaultExpiration: 5 * time.Second,
			keys:              []string{"key1", "key2"},
			values:            []string{"value1", "value2"},
			advanceDuration:   3 * time.Second,
			wantFound:         []bool{true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
			cache := newSimpleCacheWithClock[string](tt.defaultExpiration, 0, mockClock)

			for i, key := range tt.keys {
				cache.SetDefault(key, tt.values[i])
			}

			mockClock.Advance(tt.advanceDuration)
			cache.deleteExpired()

			for i, key := range tt.keys {
				_, found := cache.Get(key)
				assert.Equal(t, tt.wantFound[i], found, "Expected presence for key: %s", key)
			}
		})
	}
}

func TestSimpleCache_CleanupRoutine(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		cleanupInterval   time.Duration
		key               string
		value             string
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
			// Note: For the cleanup routine test, we still use RealClock since the
			// ticker is based on real time.
			cache := NewSimpleCache[string](tt.defaultExpiration, tt.cleanupInterval)
			cache.SetDefault(tt.key, tt.value)

			time.Sleep(tt.sleepDuration)

			_, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantFound, found, "Expected cleanup to remove expired item")
		})
	}
}

func TestSimpleCache_WithModelTypes(t *testing.T) {
	mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}

	t.Run("issuer_cache", func(t *testing.T) {
		cache := newSimpleCacheWithClock[*model.Issuer](5*time.Second, 0, mockClock)
		issuer := &model.Issuer{}
		cache.SetDefault("issuer1", issuer)

		val, found := cache.Get("issuer1")

		assert.True(t, found)
		assert.Equal(t, issuer, val)
	})

	t.Run("issuer_list_cache", func(t *testing.T) {
		cache := newSimpleCacheWithClock[[]model.Issuer](5*time.Second, 0, mockClock)
		issuers := []model.Issuer{{}, {}}
		cache.SetDefault("issuers", issuers)

		val, found := cache.Get("issuers")

		assert.True(t, found)
		assert.Equal(t, len(issuers), len(val))
	})
}

func TestBootstrapCache(t *testing.T) {
	tests := []struct {
		name           string
		config         DBConfig
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
			require.NotNil(t, caches.Issuer, "Expected Issuer cache")
			require.NotNil(t, caches.Issuers, "Expected Issuers cache")
			require.NotNil(t, caches.Redemptions, "Expected Redemptions cache")
			require.NotNil(t, caches.IssuerCohort, "Expected IssuerCohort cache")

			issuerCache, ok := caches.Issuer.(*SimpleCache[*model.Issuer])
			require.True(t, ok, "Expected Issuer cache to be *SimpleCache")
			assert.Equal(t, tt.wantExpiration, issuerCache.defaultExpiration,
				"Expected defaultExpiration for Issuer cache")
			assert.Equal(t, tt.wantCleanup, issuerCache.cleanupInterval,
				"Expected cleanupInterval for Issuer cache")
		})
	}
}
