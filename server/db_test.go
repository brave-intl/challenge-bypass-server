package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	issuerID = uuid.New()
	duration = "duration"
	now      = time.Now()
	dbConfig = DBConfig{
		ConnectionURI: "",
		CachingConfig: CachingConfig{
			Enabled:       true,
			ExpirationSec: 30,
		},
		MaxConnection:           1,
		DefaultDaysBeforeExpiry: 1,
		DefaultIssuerValidDays:  1,
		DynamodbEndpoint:        "",
	}
	issuerToCache = model.Issuer{
		ID:           &issuerID,
		IssuerType:   "0.0025BAT_0",
		IssuerCohort: 1,
		MaxTokens:    1,
		CreatedAt:    pq.NullTime{Time: time.Now(), Valid: true},
		ExpiresAt:    pq.NullTime{Time: time.Now(), Valid: true},
		RotatedAt:    pq.NullTime{Time: time.Now(), Valid: true},
		Version:      1,
		ValidFrom:    &now,
		Buffer:       1,
		Overlap:      1,
		Duration:     &duration,
		Keys:         []model.IssuerKeys{},
	}
)

func TestBootstrapDBCache(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	require.NotNil(t, caches, "Expected caches to be initialized")
	assert.NotNil(t, caches.Issuers, "Expected Issuers cache to exist")
	assert.NotNil(t, caches.Issuer, "Expected Issuer cache to exist")
	assert.NotNil(t, caches.Redemptions, "Expected Redemptions cache to exist")
	assert.NotNil(t, caches.IssuerCohort, "Expected IssuerCohort cache to exist")
}

// TestIssuerCacheRetrieval tests that getting values from the cache works
func TestIssuerCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	require.NotNil(t, caches, "Expected caches to be initialized")

	caches.Issuer.SetDefault(issuerID.String(), &issuerToCache)

	cached, ok := caches.Issuer.Get(issuerID.String())
	assert.True(t, ok, "Expected an issuer to be found in the cache")
	assert.Equal(t, &issuerToCache, cached)

	cacheMiss, ok := caches.Issuer.Get("test")
	assert.False(t, ok, "Expected a cache miss for test issuer")
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, &issuerToCache, cacheMiss)
}

// TestIssuersCacheRetrieval tests that getting values from the cache works
func TestIssuersCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	require.NotNil(t, caches, "Expected caches to be initialized")

	caches.Issuers.SetDefault(issuerToCache.IssuerType, []model.Issuer{issuerToCache})

	cached, ok := caches.Issuers.Get(issuerToCache.IssuerType)
	assert.True(t, ok, "Expected issuers to be found in the cache")
	assert.Equal(t, []model.Issuer{issuerToCache}, cached)

	cacheMiss, ok := caches.Issuers.Get("test")
	assert.False(t, ok, "Expected a cache miss for the test issuers")
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, []model.Issuer{issuerToCache}, cacheMiss)
}

// TestRedemptionsCacheRetrieval tests that getting values from the cache works
func TestRedemCacheRetrieval(t *testing.T) {
	redemption := Redemption{
		IssuerType: "0.0025BAT_0",
		ID:         uuid.New().String(),
		Timestamp:  now,
		Payload:    "",
	}

	caches := bootstrapCache(dbConfig)
	require.NotNil(t, caches, "Expected caches to be initialized")

	cacheKey := fmt.Sprintf("%s:%s", redemption.IssuerType, redemption.ID)
	caches.Redemptions.SetDefault(cacheKey, &redemption)

	cached, ok := caches.Redemptions.Get(cacheKey)
	assert.True(t, ok, "Expected a redemption to be found in the cache")
	assert.Equal(t, &redemption, cached)

	cacheMiss, ok := caches.Redemptions.Get("test")
	assert.False(t, ok, "Expected a cache miss for the test redemption")
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, &redemption, cacheMiss)
}

// TestIssuerCohortCacheRetrieval tests that getting values from the cache works
func TestIssuerCohortCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	require.NotNil(t, caches, "Expected caches to be initialized")

	caches.IssuerCohort.SetDefault(issuerToCache.IssuerType, []model.Issuer{issuerToCache})

	cached, ok := caches.IssuerCohort.Get(issuerToCache.IssuerType)
	assert.True(t, ok, "Expected issuer cohort to be found in the cache")
	assert.Equal(t, []model.Issuer{issuerToCache}, cached)

	cacheMiss, ok := caches.IssuerCohort.Get("test")
	assert.False(t, ok, "Expected a cache miss for the test issuer cohort")
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, []model.Issuer{issuerToCache}, cacheMiss)
}
