package server

import (
	"errors"
	"fmt"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Why?
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
)

// CachingConfig is how long data is cached
type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

// DbConfig defines app configurations
type DbConfig struct {
	ConnectionURI           string        `json:"connectionURI"`
	CachingConfig           CachingConfig `json:"caching"`
	MaxConnection           int           `json:"maxConnection"`
	DefaultDaysBeforeExpiry int           `json:"DefaultDaysBeforeExpiry"`
	DefaultIssuerValidDays  int           `json:"DefaultIssuerValidDays"`
}

// Issuer of tokens
type Issuer struct {
	SigningKey *crypto.SigningKey
	ID         string    `db:"id"`
	IssuerType string    `db:"issuer_type"`
	Key        []byte    `db:"signing_key"`
	MaxTokens  int       `db:"max_tokens"`
	ExpiresAt  time.Time `db:"expires_at"`
	RotatedAt  time.Time `db:"rotated_at"`
	Version    int       `db:"version"`
}

// Redemption is a token Redeemed
type Redemption struct {
	IssuerType string    `json:"issuerType" db:"issuer_type"`
	ID         string    `json:"id" db:"id"`
	Timestamp  time.Time `json:"timestamp" db:"ts"`
	Payload    string    `json:"payload" db:"payload"`
}

// RedemptionV2 is a token Redeemed
type RedemptionV2 struct {
	IssuerID  string    `json:"issuerId"`
	ID        []byte    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Payload   string    `json:"payload"`
	TTL       string    `json:"TTL"`
}

// CacheInterface cach functions
type CacheInterface interface {
	Get(k string) (interface{}, bool)
	Delete(k string)
	SetDefault(k string, x interface{})
}

var (
	errIssuerNotFound      = errors.New("Issuer with the given name does not exist")
	errDuplicateRedemption = errors.New("Duplicate Redemption")
	errRedemptionNotFound  = errors.New("Redemption with the given id does not exist")
)

// LoadDbConfig loads config into server variable
func (c *Server) LoadDbConfig(config DbConfig) {
	c.dbConfig = config
}

func (c *Server) initDb() {
	cfg := c.dbConfig

	db, err := sqlx.Open("postgres", cfg.ConnectionURI)
	if err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(cfg.MaxConnection)
	c.db = db

	driver, err := postgres.WithInstance(c.db.DB, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file:///src/migrations",
		"postgres", driver)
	if err != nil {
		panic(err)
	}
	err = m.Migrate(3)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}

	if cfg.CachingConfig.Enabled {
		c.caches = make(map[string]CacheInterface)
		defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
		c.caches["issuers"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["redemptions"] = cache.New(defaultDuration, 2*defaultDuration)
	}
}

func (c *Server) fetchIssuer(issuerID string) (*Issuer, error) {
	if c.caches != nil {
		if cached, found := c.caches["issuer"].Get(issuerID); found {
			return cached.(*Issuer), nil
		}
	}

	issuer := Issuer{}
	err := c.db.Get(issuer, `
	    SELECT * FROM issuers
	    WHERE id=$1 and retired_at IS NULL
	`, issuerID)

	if err != nil {
		return nil, errIssuerNotFound
	}

	issuer.SigningKey = &crypto.SigningKey{}
	err = issuer.SigningKey.UnmarshalText(issuer.Key)
	if err != nil {
		return nil, err
	}

	if c.caches != nil {
		c.caches["issuer"].SetDefault(issuerID, issuer)
	}

	return &issuer, nil
}

func (c *Server) fetchIssuers(issuerType string) (*[]Issuer, error) {
	if c.caches != nil {
		if cached, found := c.caches["issuers"].Get(issuerType); found {
			return cached.(*[]Issuer), nil
		}
	}

	issuers := []Issuer{}
	err := c.db.Select(
		issuers,
		`SELECT *
		FROM issuers 
		WHERE issuer_type=$1 AND retired_at IS NULL
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`, issuerType)
	if err != nil {
		return nil, err
	}

	if len(issuers) < 1 {
		return nil, errIssuerNotFound
	}

	for _, issuer := range issuers {
		issuer.SigningKey = &crypto.SigningKey{}
		err := issuer.SigningKey.UnmarshalText(issuer.Key)
		if err != nil {
			return nil, err
		}
	}

	if c.caches != nil {
		c.caches["issuers"].SetDefault(issuerType, issuers)
	}

	return &issuers, nil
}

// RotateIssuers is the function that rotates
func RotateIssuers(c Server) (bool, error) {
	cfg := c.dbConfig

	tx := c.db.MustBegin()

	defer tx.Rollback()

	issuers := []Issuer{}
	err := tx.Select(
		issuers,
		`SELECT id, issuer_type, expires_at, max_tokens FROM issuers 
			WHERE expires_at IS NOT NULL
			AND rotated_at IS NULL
			AND expires_at < NOW() + $1 * INTERVAL '1 day'
			AND expires_at > NOW()
		FOR UPDATE SKIP LOCKED`, cfg.DefaultDaysBeforeExpiry,
	)
	if err != nil {
		return true, err
	}

	for _, issuer := range issuers {
		if issuer.MaxTokens == 0 {
			issuer.MaxTokens = 40
		}

		signingKey, err := crypto.RandomSigningKey()
		if err != nil {
			return true, err
		}

		signingKeyTxt, err := signingKey.MarshalText()
		if err != nil {
			return true, err
		}

		if _, err = tx.Exec(
			`INSERT INTO issuers(issuer_type, signing_key, max_tokens, expires_at, version) VALUES ($1, $2, $3, $4, 2)`,
			issuer.IssuerType,
			signingKeyTxt,
			issuer.MaxTokens,
			issuer.ExpiresAt.AddDate(0, 0, cfg.DefaultIssuerValidDays),
		); err != nil {
			return true, err
		}
		if _, err = tx.Exec(
			`UPDATE issuers SET rotated_at = now() where id = $1`,
			issuer.ID,
		); err != nil {
			return true, err
		}
	}

	if err := tx.Commit(); err != nil {
		return true, err
	}

	return true, nil
}

func (c *Server) createIssuer(issuerType string, maxTokens int, expiresAt *time.Time) error {
	if maxTokens == 0 {
		maxTokens = 40
	}

	signingKey, err := crypto.RandomSigningKey()
	if err != nil {
		return err
	}

	signingKeyTxt, err := signingKey.MarshalText()
	if err != nil {
		return err
	}

	rows, err := c.db.Query(
		`INSERT INTO issuers(issuer_type, signing_key, max_tokens, expires_at, version) VALUES ($1, $2, $3, $4, 2)`,
		issuerType,
		signingKeyTxt,
		maxTokens,
		expiresAt,
	)
	if err != nil {
		return err
	}

	if c.caches != nil {
		if _, found := c.caches["issuers"].Get(issuerType); found {
			c.caches["issuers"].Delete(issuerType)
		}
	}

	defer rows.Close()
	return nil
}

func (c *Server) redeemToken(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	if issuer.Version == 1 {
		rows, err := c.db.Query(
			`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, issuer.IssuerType, payload)
		if err != nil {
			if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
				return errDuplicateRedemption
			}
			return err
		}
		defer rows.Close()
		return nil
	}

	err = c.redeemTokenV2(issuer.ID, preimageTxt, payload)

	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
			return errDuplicateRedemption
		}
		return err
	}

	return nil
}

func (c *Server) fetchRedemption(issuerType, ID string) (*Redemption, error) {
	if c.caches != nil {
		if cached, found := c.caches["redemptions"].Get(fmt.Sprintf("%s:%s", issuerType, ID)); found {
			return cached.(*Redemption), nil
		}
	}

	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions WHERE id = $1 AND issuer_type = $2`, ID, issuerType)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if rows.Next() {
		var redemption = &Redemption{}
		if err := rows.Scan(&redemption.ID, &redemption.IssuerType, &redemption.Timestamp, &redemption.Payload); err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerType, ID), redemption)
		}

		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, errRedemptionNotFound
}

func (c *Server) fetchRedemptionV2(issuerID, ID string) (*RedemptionV2, error) {
	if c.caches != nil {
		if cached, found := c.caches["redemptionsV2"].Get(fmt.Sprintf("%s:%s", issuerID, ID)); found {
			return cached.(*RedemptionV2), nil
		}
	}

	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions_v2 WHERE id = $1 AND issuer_id = $2`, ID, issuerID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if rows.Next() {
		var redemption = &RedemptionV2{}
		if err := rows.Scan(&redemption.ID, &redemption.IssuerID, &redemption.Timestamp, &redemption.Payload); err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerID, ID), redemption)
		}

		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, errRedemptionNotFound
}
