package server

import (
	"fmt"
	"testing"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
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

	issuerToCache = Issuer{
		SigningKey:   &crypto.SigningKey{},
		ID:           &issuerID,
		IssuerType:   "0.0025BAT_0",
		IssuerCohort: 1,
		MaxTokens:    1,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now(),
		RotatedAt:    time.Now(),
		Version:      1,
		ValidFrom:    &now,
		Buffer:       1,
		Overlap:      1,
		Duration:     &duration,
		Keys:         []IssuerKeys{},
	}
)

func TestBootstrapCache(t *testing.T) {
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

	cached := retrieveFromCache(caches, "issuer", issuerID.String())
	cacheMiss := retrieveFromCache(caches, "issuer", "test")

	assert.Equal(t, cached.(*Issuer), &issuerToCache)
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, &issuerToCache)
	assert.Panics(t, func() {
		_, ok := cacheMiss.(*Issuer)
		if ok != true {
			// Satisfy linter
			panic("Bad assertion")
		}
	})
}

// TestIssuersCacheRetrieval tests that getting values from the cache works
func TestIssuersCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	caches["issuers"].SetDefault(issuerToCache.IssuerType, []Issuer{issuerToCache})

	cached := retrieveFromCache(caches, "issuers", issuerToCache.IssuerType)
	cacheMiss := retrieveFromCache(caches, "issuers", "test")

	assert.Equal(t, cached.([]Issuer), []Issuer{issuerToCache})
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, []Issuer{issuerToCache})
	assert.Panics(t, func() {
		_, ok := cacheMiss.([]Issuer)
		if ok != true {
			// Satisfy linter
			panic("Bad assertion")
		}
	})
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

	cached := retrieveFromCache(caches, "redemptions", fmt.Sprintf("%s:%s", redemption.IssuerType, redemption.ID))
	cacheMiss := retrieveFromCache(caches, "redemptions", "test")

	assert.Equal(t, cached.(*Redemption), &redemption)
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, &redemption)
	assert.Panics(t, func() {
		_, ok := cacheMiss.(*Redemption)
		if ok != true {
			// Satisfy linter
			panic("Bad assertion")
		}
	})
}

// TestIssuerCohortCacheRetrieval tests that getting values from the cache works
func TestIssuerCohortCacheRetrieval(t *testing.T) {
	caches := bootstrapCache(dbConfig)
	caches["issuercohort"].SetDefault(issuerToCache.IssuerType, []Issuer{issuerToCache})

	cached := retrieveFromCache(caches, "issuercohort", issuerToCache.IssuerType)
	cacheMiss := retrieveFromCache(caches, "issuercohort", "test")

	assert.Equal(t, cached.([]Issuer), []Issuer{issuerToCache})
	assert.Nil(t, cacheMiss)
	assert.NotEqual(t, cacheMiss, []Issuer{issuerToCache})
	assert.Panics(t, func() {
		_, ok := cacheMiss.([]Issuer)
		if ok != true {
			// Satisfy linter
			panic("Bad assertion")
		}
	})
}
