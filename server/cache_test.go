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
		value             testStruct
		wantStored        bool
	}{
		{
			name:              "set_struct_value",
			defaultExpiration: 5 * time.Second,
			key:               "structkey",
			value:             testStruct{A: 9, B: "b"},
			wantStored:        true,
		},
		{
			name:              "set_with_no_expiration",
			defaultExpiration: 0,
			key:               "noexpire",
			value:             testStruct{A: 1, B: "persist"},
			wantStored:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
			cache := newSimpleCacheWithClock[testStruct](tt.defaultExpiration, 0, mockClock)

			cache.SetDefault(tt.key, tt.value)

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
		{
			name:              "get_before_expiration",
			defaultExpiration: 50 * time.Millisecond,
			setupKey:          "expirekey",
			setupValue:        "value",
			getKey:            "expirekey",
			wantValue:         "value",
			wantFound:         true,
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

func TestSimpleCache_Get_Expiration(t *testing.T) {
	tests := []struct {
		name              string
		defaultExpiration time.Duration
		key               string
		value             int
		advanceDuration   time.Duration
		wantFound         bool
	}{
		{
			name:              "expired_item_not_found",
			defaultExpiration: 50 * time.Millisecond,
			key:               "expirekey",
			value:             42,
			advanceDuration:   80 * time.Millisecond,
			wantFound:         false,
		},
		{
			name:              "no_expiration_persists",
			defaultExpiration: 0,
			key:               "nokey",
			value:             99,
			advanceDuration:   30 * time.Millisecond,
			wantFound:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
			cache := newSimpleCacheWithClock[int](tt.defaultExpiration, 0, mockClock)

			cache.SetDefault(tt.key, tt.value)

			// Advance the mock clock instead of sleeping
			mockClock.Advance(tt.advanceDuration)

			_, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantFound, found, "Expected expiration behavior")
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
			// ticker is based on real time. However, we could refactor the cleanup
			// to also use the clock if we wanted more control.
			cache := NewSimpleCache[string](tt.defaultExpiration, tt.cleanupInterval)
			cache.SetDefault(tt.key, tt.value)

			time.Sleep(tt.sleepDuration)

			_, found := cache.Get(tt.key)
			assert.Equal(t, tt.wantFound, found, "Expected cleanup to remove expired item")
		})
	}
}

func TestSimpleCache_MultipleTypes(t *testing.T) {
	t.Run("store_string", func(t *testing.T) {
		mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
		cache := newSimpleCacheWithClock[string](0, 0, mockClock)
		cache.SetDefault("str", "hello")
		val, found := cache.Get("str")
		require.True(t, found, "Expected key to be found")
		assert.Equal(t, "hello", val, "Expected correct value")
	})

	t.Run("store_int", func(t *testing.T) {
		mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
		cache := newSimpleCacheWithClock[int](0, 0, mockClock)
		cache.SetDefault("int", 123)
		val, found := cache.Get("int")
		require.True(t, found, "Expected key to be found")
		assert.Equal(t, 123, val, "Expected correct value")
	})

	type testStruct struct {
		A int
		B string
	}
	t.Run("store_struct", func(t *testing.T) {
		mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
		cache := newSimpleCacheWithClock[testStruct](0, 0, mockClock)
		expected := testStruct{A: 9, B: "b"}
		cache.SetDefault("struct", expected)
		val, found := cache.Get("struct")
		require.True(t, found, "Expected key to be found")
		assert.Equal(t, expected, val, "Expected correct value")
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

			assert.Equal(t, tt.wantExpiration, caches.Issuer.defaultExpiration,
				"Expected defaultExpiration for Issuer cache")
			assert.Equal(t, tt.wantCleanup, caches.Issuer.cleanupInterval,
				"Expected cleanupInterval for Issuer cache")
		})
	}
}

// New test specifically for clock-based expiration
func TestSimpleCache_ExpirationWithMockClock(t *testing.T) {
	mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	cache := newSimpleCacheWithClock[string](5*time.Second, 0, mockClock)

	// Set a value
	cache.SetDefault("key", "value")

	// Verify it exists
	val, found := cache.Get("key")
	assert.True(t, found)
	assert.Equal(t, "value", val)

	// Advance time by 3 seconds (not expired yet)
	mockClock.Advance(3 * time.Second)
	val, found = cache.Get("key")
	assert.True(t, found)
	assert.Equal(t, "value", val)

	// Advance time by 3 more seconds (now expired: total 6 seconds)
	mockClock.Advance(3 * time.Second)
	val, found = cache.Get("key")
	assert.False(t, found)
	assert.Equal(t, "", val)
}

// Test that deleteExpired works with mock clock
func TestSimpleCache_DeleteExpiredWithMockClock(t *testing.T) {
	mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	cache := newSimpleCacheWithClock[string](5*time.Second, 0, mockClock)

	// Add multiple items
	cache.SetDefault("key1", "value1")
	cache.SetDefault("key2", "value2")
	cache.SetDefault("key3", "value3")

	// Advance time past expiration
	mockClock.Advance(6 * time.Second)

	// Manually trigger cleanup
	cache.deleteExpired()

	// All items should be gone
	_, found := cache.Get("key1")
	assert.False(t, found)
	_, found = cache.Get("key2")
	assert.False(t, found)
	_, found = cache.Get("key3")
	assert.False(t, found)
}

// Test with actual model types
func TestSimpleCache_WithModelTypes(t *testing.T) {
	mockClock := &MockClock{CurrentTime: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}

	t.Run("issuer_cache", func(t *testing.T) {
		cache := newSimpleCacheWithClock[*model.Issuer](5*time.Second, 0, mockClock)
		issuer := &model.Issuer{} // Assuming Issuer is a struct in model package
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
