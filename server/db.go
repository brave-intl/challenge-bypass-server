package server

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Why?
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
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
	DynamodbEndpoint        string        `json:"DynamodbEndpoint"`
}

type issuer struct {
	ID           string      `db:"id"`
	IssuerType   string      `db:"issuer_type"`
	IssuerCohort int         `db:"issuer_cohort"`
	SigningKey   []byte      `db:"signing_key"`
	MaxTokens    int         `db:"max_tokens"`
	CreatedAt    pq.NullTime `db:"created_at"`
	ExpiresAt    pq.NullTime `db:"expires_at"`
	RotatedAt    pq.NullTime `db:"rotated_at"`
	Version      int         `db:"version"`
}

// Issuer of tokens
type Issuer struct {
	SigningKey   *crypto.SigningKey
	ID           string    `json:"id"`
	IssuerType   string    `json:"issuer_type"`
	IssuerCohort int       `json:"issuer_cohort"`
	MaxTokens    int       `json:"max_tokens"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	RotatedAt    time.Time `json:"rotated_at"`
	Version      int       `json:"version"`
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
	ID        string    `json:"id"`
	PreImage  string    `json:"preImage"`
	Timestamp time.Time `json:"timestamp"`
	Payload   string    `json:"payload"`
	TTL       int64     `json:"TTL"`
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

	// Database Telemetry (open connections, etc)
	// Create a new collector, the name will be used as a label on the metrics
	collector := metrics.NewStatsCollector("challenge_bypass_db", db)
	// Register it with Prometheus
	err = prometheus.Register(collector)

	if ae, ok := err.(prometheus.AlreadyRegisteredError); ok {
		// take old collector, and add the new db
		if sc, ok := ae.ExistingCollector.(*metrics.StatsCollector); ok {
			sc.AddStatsGetter("challenge_bypass_db", db)
		}
	}

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
	err = m.Migrate(5)
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

var (
	fetchIssuerCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fetch_issuer_count",
		Help: "Number of fetch issuer attempts",
	})

	createIssuerCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "create_issuer_count",
		Help: "Number of create issuer attempts",
	})

	redeemTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "redeem_token_count",
		Help: "Number of calls to redeem token",
	})

	fetchRedemptionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fetch_redemption_count",
		Help: "Number of calls to fetch redemption",
	})

	// Timers for SQL calls
	latencyBuckets = []float64{.25, .5, 1, 2.5, 5, 10}

	fetchIssuerByTypeDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_fetch_issuer_by_type_duration",
		Help:    "select issuer by type sql call duration",
		Buckets: latencyBuckets,
	})

	createIssuerDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_create_issuer_duration",
		Help:    "create issuer sql call duration",
		Buckets: latencyBuckets,
	})

	createRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_create_redemption_duration",
		Help:    "create redemption sql call duration",
		Buckets: latencyBuckets,
	})

	fetchRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_fetch_redemption_duration",
		Help:    "fetch redemption sql call duration",
		Buckets: latencyBuckets,
	})
)

func incrementCounter(c prometheus.Counter) {
	c.Add(1)
}

func (c *Server) fetchIssuer(issuerID string) (*Issuer, error) {
	defer incrementCounter(fetchIssuerCounter)

	if c.caches != nil {
		if cached, found := c.caches["issuer"].Get(issuerID); found {
			return cached.(*Issuer), nil
		}
	}

	fetchedIssuer := issuer{}
	queryTimer := prometheus.NewTimer(fetchIssuerByTypeDBDuration)
	err := c.db.Get(&fetchedIssuer, `
	    SELECT * FROM issuers
	    WHERE id=$1
	`, issuerID)

	if err != nil {
		return nil, errIssuerNotFound
	}

	issuer, err := convertDBIssuer(fetchedIssuer)
	if err != nil {
		return nil, err
	}
	queryTimer.ObserveDuration()

	issuer.SigningKey = &crypto.SigningKey{}
	err = issuer.SigningKey.UnmarshalText(fetchedIssuer.SigningKey)
	if err != nil {
		return nil, err
	}

	if c.caches != nil {
		c.caches["issuer"].SetDefault(issuerID, issuer)
	}

	return issuer, nil
}

func (c *Server) fetchIssuers(issuerType string) (*[]Issuer, error) {
	if c.caches != nil {
		if cached, found := c.caches["issuers"].Get(issuerType); found {
			return cached.(*[]Issuer), nil
		}
	}

	fetchedIssuers := []issuer{}
	err := c.db.Select(
		&fetchedIssuers,
		`SELECT *
		FROM issuers 
		WHERE issuer_type=$1
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`, issuerType)
	if err != nil {
		return nil, err
	}

	if len(fetchedIssuers) < 1 {
		return nil, errIssuerNotFound
	}

	issuers := []Issuer{}
	for _, fetchedIssuer := range fetchedIssuers {
		issuer, err := convertDBIssuer(fetchedIssuer)
		if err != nil {
			return nil, err
		}

		issuers = append(issuers, *issuer)
	}

	if c.caches != nil {
		c.caches["issuers"].SetDefault(issuerType, issuers)
	}

	return &issuers, nil
}

func (c *Server) fetchAllIssuers() (*[]Issuer, error) {
	fetchedIssuers := []issuer{}
	err := c.db.Select(
		&fetchedIssuers,
		`SELECT *
		FROM issuers
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`)
	if err != nil {
		return nil, err
	}

	issuers := []Issuer{}
	for _, fetchedIssuer := range fetchedIssuers {
		issuer, err := convertDBIssuer(fetchedIssuer)
		if err != nil {
			return nil, err
		}

		issuers = append(issuers, *issuer)
	}

	return &issuers, nil
}

// RotateIssuers is the function that rotates
func (c *Server) rotateIssuers() error {
	cfg := c.dbConfig

	tx := c.db.MustBegin()

	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	fetchedIssuers := []issuer{}
	err = tx.Select(
		&fetchedIssuers,
		`SELECT * FROM issuers 
			WHERE expires_at IS NOT NULL
			AND rotated_at IS NULL
			AND expires_at < NOW() + $1 * INTERVAL '1 day'
		FOR UPDATE SKIP LOCKED`, cfg.DefaultDaysBeforeExpiry,
	)
	if err != nil {
		return err
	}

	for _, fetchedIssuer := range fetchedIssuers {
		issuer := Issuer{
			ID:           fetchedIssuer.ID,
			IssuerType:   fetchedIssuer.IssuerType,
			IssuerCohort: fetchedIssuer.IssuerCohort,
			MaxTokens:    fetchedIssuer.MaxTokens,
			ExpiresAt:    fetchedIssuer.ExpiresAt.Time,
			RotatedAt:    fetchedIssuer.RotatedAt.Time,
			CreatedAt:    fetchedIssuer.CreatedAt.Time,
			Version:      fetchedIssuer.Version,
		}

		if issuer.MaxTokens == 0 {
			issuer.MaxTokens = 40
		}

		signingKey, err := crypto.RandomSigningKey()
		if err != nil {
			return err
		}

		signingKeyTxt, err := signingKey.MarshalText()
		if err != nil {
			return err
		}

		if _, err = tx.Exec(
			`INSERT INTO issuers(issuer_type, issuer_cohort, signing_key, max_tokens, expires_at, version) VALUES ($1, $2, $3, $4, $5, 2)`,
			issuer.IssuerType,
			issuer.IssuerCohort,
			signingKeyTxt,
			issuer.MaxTokens,
			issuer.ExpiresAt.AddDate(0, 0, cfg.DefaultIssuerValidDays),
		); err != nil {
			return err
		}
		if _, err = tx.Exec(
			`UPDATE issuers SET rotated_at = now() where id = $1`,
			fetchedIssuer.ID,
		); err != nil {
			return err
		}
	}

	return nil
}

func (c *Server) createIssuer(issuerType string, issuerCohort int, maxTokens int, expiresAt *time.Time) error {
	defer incrementCounter(createIssuerCounter)
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

	queryTimer := prometheus.NewTimer(createIssuerDBDuration)
	rows, err := c.db.Query(
		`INSERT INTO issuers(issuer_type, issuer_cohort, signing_key, max_tokens, expires_at, version) VALUES ($1, $2, $3, $4, $5, 2)`,
		issuerType,
		issuerCohort,
		signingKeyTxt,
		maxTokens,
		expiresAt,
	)
	if err != nil {
		return err
	}
	queryTimer.ObserveDuration()

	if c.caches != nil {
		if _, found := c.caches["issuers"].Get(issuerType); found {
			c.caches["issuers"].Delete(issuerType)
		}
	}

	defer rows.Close()
	return nil
}

type Queryable interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func (c *Server) redeemToken(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	defer incrementCounter(redeemTokenCounter)
	if issuer.Version == 1 {
		return redeemTokenWithDB(c.db, issuer.IssuerType, preimage, payload)
	} else if issuer.Version == 2 {
		return c.redeemTokenV2(issuer, preimage, payload)
	}
	return errors.New("Wrong Issuer Version")
}

func redeemTokenWithDB(db Queryable, issuer string, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	queryTimer := prometheus.NewTimer(createRedemptionDBDuration)
	rows, err := db.Query(
		`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, issuer, payload)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
			return errDuplicateRedemption
		}
		return err
	}
	defer rows.Close()

	queryTimer.ObserveDuration()
	return nil
}

func (c *Server) fetchRedemption(issuerType, ID string) (*Redemption, error) {
	defer incrementCounter(fetchRedemptionCounter)
	if c.caches != nil {
		if cached, found := c.caches["redemptions"].Get(fmt.Sprintf("%s:%s", issuerType, ID)); found {
			return cached.(*Redemption), nil
		}
	}

	queryTimer := prometheus.NewTimer(fetchRedemptionDBDuration)
	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions WHERE id = $1 AND issuer_type = $2`, ID, issuerType)

	queryTimer.ObserveDuration()

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

func convertDBIssuer(issuer issuer) (*Issuer, error) {
	Issuer := Issuer{
		ID:           issuer.ID,
		IssuerType:   issuer.IssuerType,
		IssuerCohort: issuer.IssuerCohort,
		MaxTokens:    issuer.MaxTokens,
		Version:      issuer.Version,
	}
	if issuer.ExpiresAt.Valid {
		Issuer.ExpiresAt = issuer.ExpiresAt.Time
	}
	if issuer.CreatedAt.Valid {
		Issuer.CreatedAt = issuer.CreatedAt.Time
	}
	if issuer.RotatedAt.Valid {
		Issuer.RotatedAt = issuer.RotatedAt.Time
	}

	Issuer.SigningKey = &crypto.SigningKey{}
	err := Issuer.SigningKey.UnmarshalText(issuer.SigningKey)
	if err != nil {
		return nil, err
	}

	return &Issuer, nil
}
