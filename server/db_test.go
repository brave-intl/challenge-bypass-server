package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/lib/pq"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
	assert.Contains(t, caches, "issuers")
	assert.Contains(t, caches, "issuer")
	assert.Contains(t, caches, "redemptions")
	assert.Contains(t, caches, "issuercohort")
}

// TestIssuerCacheRetrieval tests that getting values from the cache works
func TestIssuerCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	caches["issuer"].SetDefault(issuerID.String(), &issuerToCache)

	cached, ok := retrieveFromCache[*model.Issuer](caches, "issuer", issuerID.String())
	assert.True(t, ok, "Expected an issuer to be found in the cache")
	cacheMiss, ok := retrieveFromCache[*model.Issuer](caches, "issuer", "test")
	assert.False(t, ok, "Expected a cache miss for test issuer")

	assert.Equal(t, cached, &issuerToCache)
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, &issuerToCache)
}

// TestIssuersCacheRetrieval tests that getting values from the cache works
func TestIssuersCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	caches["issuers"].SetDefault(issuerToCache.IssuerType, []model.Issuer{issuerToCache})

	cached, ok := retrieveFromCache[[]model.Issuer](caches, "issuers", issuerToCache.IssuerType)
	assert.True(t, ok, "Expected issuers to be found in the cache")
	cacheMiss, ok := retrieveFromCache[[]model.Issuer](caches, "issuers", "test")
	assert.False(t, ok, "Expected a cache miss for the test issuers")

	assert.Equal(t, cached, []model.Issuer{issuerToCache})
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, []model.Issuer{issuerToCache})
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
	caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", redemption.IssuerType, redemption.ID), &redemption)

	cached, ok := retrieveFromCache[*Redemption](caches, "redemptions", fmt.Sprintf("%s:%s", redemption.IssuerType, redemption.ID))
	assert.True(t, ok, "Expected a redemption to be found in the cache")
	cacheMiss, ok := retrieveFromCache[*Redemption](caches, "redemptions", "test")
	assert.False(t, ok, "Expected a cache miss for the test redemption")

	assert.Equal(t, cached, &redemption)
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, &redemption)
}

// TestIssuerCohortCacheRetrieval tests that getting values from the cache works
func TestIssuerCohortCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	caches["issuercohort"].SetDefault(issuerToCache.IssuerType, []model.Issuer{issuerToCache})

	cached, ok := retrieveFromCache[[]model.Issuer](caches, "issuercohort", issuerToCache.IssuerType)
	assert.True(t, ok, "Expected redemptions to be found in the cache")
	cacheMiss, ok := retrieveFromCache[[]model.Issuer](caches, "issuercohort", "test")
	assert.False(t, ok, "Expected a cache miss for the test redemptions")

	assert.Equal(t, cached, []model.Issuer{issuerToCache})
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, []model.Issuer{issuerToCache})
}
