package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"

	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"

	timeutils "github.com/brave-intl/bat-go/libs/time"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
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

// DBConfig defines app configurations
type DBConfig struct {
	ConnectionURI           string        `json:"connectionURI"`
	CachingConfig           CachingConfig `json:"caching"`
	MaxConnection           int           `json:"maxConnection"`
	DefaultDaysBeforeExpiry int           `json:"DefaultDaysBeforeExpiry"`
	DefaultIssuerValidDays  int           `json:"DefaultIssuerValidDays"`
	DynamodbEndpoint        string        `json:"DynamodbEndpoint"`
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
	Offset    int64     `json:"offset"`
}

// CacheInterface cache functions
type CacheInterface interface {
	Get(k string) (interface{}, bool)
	Delete(k string)
	SetDefault(k string, x interface{})
}

var (
	errIssuerNotFound       = errors.New("issuer with the given name does not exist")
	errIssuerCohortNotFound = errors.New("issuer with the given name and cohort does not exist")
	errDuplicateRedemption  = errors.New("duplicate Redemption")
	errRedemptionNotFound   = errors.New("redemption with the given id does not exist")
)

// LoadDBConfig loads config into server variable
func (c *Server) LoadDBConfig(config DBConfig) {
	c.dbConfig = config
}

// InitDB initialzes the database connection based on a server's configuration
func (c *Server) InitDB() {
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

	if os.Getenv("ENV") != "production" {
		time.Sleep(10 * time.Second)
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
	err = m.Migrate(7)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}

	if cfg.CachingConfig.Enabled {
		c.caches = bootstrapCache(cfg)
	}
}

var (
	fetchIssuerTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_fetch_issuer_total",
		Help: "Number of fetch issuer attempts",
	})

	createIssuerTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_create_issuer_total",
		Help: "Number of create issuer attempts",
	})

	redeemTokenTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_redeem_token_total",
		Help: "Number of calls to redeem token",
	})

	fetchRedemptionTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_fetch_redemption_total",
		Help: "Number of calls to fetch redemption",
	})

	// Timers for SQL calls
	latencyBuckets = []float64{.25, .5, 1, 2.5, 5, 10}

	fetchIssuerByTypeDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cbp_db_fetch_issuer_by_type_duration",
		Help:    "select issuer by type sql call duration",
		Buckets: latencyBuckets,
	})

	createIssuerDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cbp_db_create_issuer_duration",
		Help:    "create issuer sql call duration",
		Buckets: latencyBuckets,
	})

	createTimeLimitedIssuerDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cbp_db_create_time_limited_issuer_duration",
		Help:    "create issuer sql call duration",
		Buckets: latencyBuckets,
	})

	createRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cbp_db_create_redemption_duration",
		Help:    "create redemption sql call duration",
		Buckets: latencyBuckets,
	})

	fetchRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cbp_db_fetch_redemption_duration",
		Help:    "fetch redemption sql call duration",
		Buckets: latencyBuckets,
	})
)

func incrementTotal(c prometheus.Counter) {
	c.Add(1)
}

func (c *Server) fetchIssuer(issuerID string) (*model.Issuer, error) {
	defer incrementTotal(fetchIssuerTotal)

	if cached := retrieveFromCache(c.caches, "issuer", issuerID); cached != nil {
		if issuer, ok := cached.(*model.Issuer); ok {
			return issuer, nil
		}
	}

	var fetchedIssuer model.Issuer
	err := c.db.Select(&fetchedIssuer, `
	    SELECT * FROM v3_issuers
	    WHERE issuer_id=$1
	`, issuerID)

	if err != nil {
		return nil, utils.ProcessingErrorFromError(errIssuerNotFound, !isPostgresNotFoundError(err))
	}

	fetchedKeys, err := c.fetchIssuerKeys([]model.Issuer{fetchedIssuer})
	if err != nil {
		return nil, err
	}

	convertedIssuer := &fetchedKeys[0]
	if c.caches != nil {
		c.caches["issuer"].SetDefault(issuerID, convertedIssuer)
	}

	return convertedIssuer, nil
}

// fetchIssuersByCohort was created to fetch multiple issuers based on their cohort when
// the Ads implementation had non-unique issuer types. This is no longer the case and this
// function should be refactored or removed. For now, it will return an array of a single
// issuer.
func (c *Server) fetchIssuersByCohort(
	issuerType string,
	issuerCohort int16,
	queryTemplate string,
) ([]model.Issuer, error) {
	// will not lose resolution int16->int
	if cached := retrieveFromCache(c.caches, "issuercohort", issuerType); cached != nil {
		if issuers, ok := cached.([]model.Issuer); ok {
			return issuers, nil
		}
	}

	var fetchedIssuers []model.Issuer
	err := c.db.Select(&fetchedIssuers, queryTemplate, issuerType, issuerCohort)
	if err != nil {
		c.Logger.Error("Failed to extract issuers from DB")
		return nil, utils.ProcessingErrorFromError(err, isPostgresNotFoundError(err))
	}

	if len(fetchedIssuers) < 1 {
		return nil, utils.ProcessingErrorFromError(errIssuerCohortNotFound, false)
	}

	issuersWithKey, err := c.fetchIssuerKeys(fetchedIssuers)
	if err != nil {
		return nil, err
	}

	if c.caches != nil {
		c.caches["issuercohort"].SetDefault(issuerType, issuersWithKey)
	}

	return issuersWithKey, nil
}

func (c *Server) fetchIssuerByType(ctx context.Context, issuerType string) (*model.Issuer, error) {
	if cached := retrieveFromCache(c.caches, "issuer", issuerType); cached != nil {
		if issuer, ok := cached.(*model.Issuer); ok {
			return issuer, nil
		}
	}

	var issuerV3 model.Issuer
	err := c.db.GetContext(ctx, &issuerV3,
		`SELECT *
		FROM v3_issuers
		WHERE issuer_type=$1
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`, issuerType)
	if err != nil {
		return nil, err
	}

	fetchedKeys, err := c.fetchIssuerKeys([]model.Issuer{issuerV3})
	if err != nil {
		return nil, err
	}

	convertedIssuer := &fetchedKeys[0]
	if c.caches != nil {
		c.caches["issuer"].SetDefault(issuerType, convertedIssuer)
	}

	return convertedIssuer, nil
}

// FetchAllIssuers fetches issuers from a cache or a database based on their type, saving them in the cache
// if it has to query the database.
func (c *Server) FetchAllIssuers() ([]model.Issuer, error) {
	if cached := retrieveFromCache(c.caches, "issuers", "all"); cached != nil {
		if issuers, ok := cached.([]model.Issuer); ok {
			return issuers, nil
		}
	}

	var err error
	var fetchedIssuers []model.Issuer
	err = c.db.Select(
		&fetchedIssuers,
		`SELECT * FROM v3_issuers ORDER BY expires_at DESC NULLS LAST, created_at DESC`,
	)

	if err != nil {
		c.Logger.Error("Failed to extract issuers from DB")
		return nil, utils.ProcessingErrorFromError(err, !isPostgresNotFoundError(err))
	}

	results := make([]model.Issuer, len(fetchedIssuers))
	for idx, currIssuer := range fetchedIssuers {
		var keys []model.IssuerKeys
		sErr := c.db.Select(
			&keys,
			`SELECT *
			FROM v3_issuer_keys 
			WHERE issuer_id=$1
			  AND (end_at > now() OR end_at IS NULL) 
			  AND (start_at <= now() OR start_at IS NULL)
			ORDER BY end_at ASC NULLS LAST, start_at ASC, created_at ASC`,
			currIssuer.ID,
		)

		if sErr != nil {
			isNotPostgresNotFoundError := !isPostgresNotFoundError(sErr)
			if isNotPostgresNotFoundError {
				c.Logger.Error("Issuer key was not found in DB")
			}
			return nil, utils.ProcessingErrorFromError(sErr, isNotPostgresNotFoundError)
		}

		currIssuer.Keys = append(currIssuer.Keys, keys...)
		results[idx] = currIssuer
	}

	if c.caches != nil {
		c.caches["issuers"].SetDefault("all", results)
	}

	return results, nil
}

func (c *Server) fetchIssuerKeys(fetchedIssuers []model.Issuer) ([]model.Issuer, error) {
	var issuers []model.Issuer
	for _, fetchedIssuer := range fetchedIssuers {
		var keys []model.IssuerKeys
		var err error

		lteVersionTwo := fetchedIssuer.Version <= 2
		err = c.db.Select(
			&keys,
			`SELECT *
			FROM v3_issuer_keys 
			WHERE issuer_id=$1
			  AND ($2 OR end_at > now())
			ORDER BY end_at ASC NULLS FIRST, start_at ASC`,
			fetchedIssuer.ID, lteVersionTwo,
		)

		if err != nil {
			isNotPostgresNotFoundError := !isPostgresNotFoundError(err)
			if isNotPostgresNotFoundError {
				c.Logger.Error("Issuer key was not found in DB")
			}
			return nil, utils.ProcessingErrorFromError(err, isNotPostgresNotFoundError)
		}

		fetchedIssuer.Keys = append(fetchedIssuer.Keys, keys...)

		issuers = append(issuers, fetchedIssuer)
	}

	return issuers, nil
}

// RotateIssuers is the function that rotates
func (c *Server) rotateIssuers() error {
	cfg := c.dbConfig

	tx := c.db.MustBegin()

	var err error

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	var fetchedIssuers []model.Issuer
	err = tx.Select(
		&fetchedIssuers,
		`SELECT * FROM v3_issuers
			WHERE expires_at IS NOT NULL
			AND last_rotated_at < NOW() - $1 * INTERVAL '1 day'
			AND expires_at < NOW() + $1 * INTERVAL '1 day'
			AND version <= 2
		FOR UPDATE SKIP LOCKED`, cfg.DefaultDaysBeforeExpiry,
	)
	if err != nil {
		return err
	}

	for _, v := range fetchedIssuers {
		// populate keys in db
		if err := txPopulateIssuerKeys(c.Logger, tx, v); err != nil {
			return fmt.Errorf("failed to populate v3 issuer keys: %w", err)
		}

		if _, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() where issuer_id = $1`,
			v.ID,
		); err != nil {
			return err
		}
	}

	return nil
}

// RotateIssuersV3 is the function that rotates time aware issuers
func (c *Server) RotateIssuersV3() error {
	return c.rotateIssuersV3()
}

// rotateIssuersV3 is the function implementation that rotates time aware issuers
func (c *Server) rotateIssuersV3() error {
	tx := c.db.MustBegin()

	var err error

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	var fetchedIssuers []model.Issuer
	// we need to get all the v3 issuers that are
	// 1. not expired
	// 2. now is after valid_from
	// 3. have max(issuer_v3.end_at) < buffer

	err = tx.Select(
		&fetchedIssuers,
		`
		select
			i.issuer_id, i.issuer_type, i.issuer_cohort, i.max_tokens, i.version,i.buffer, i.valid_from, i.last_rotated_at, i.expires_at, i.duration,i.created_at, i.overlap
		from
			v3_issuers i
		where
			i.version = 3 and
			i.expires_at is not null and
			i.expires_at > now()
			and (select max(end_at) from v3_issuer_keys where issuer_id=i.issuer_id) < now()
				+ i.buffer * i.duration::interval
				+ i.overlap * i.duration::interval -1 * i.duration::interval
		for update skip locked
		`,
	)
	if err != nil {
		return err
	}

	// for each issuer fetched
	for _, issuer := range fetchedIssuers {
		var fetchIssuerKeys []model.IssuerKeys
		// get all the future keys for this issuer
		err = tx.Select(
			&fetchIssuerKeys,
			`SELECT *
			FROM v3_issuer_keys where issuer_id=$1 and end_at > now()
			ORDER BY end_at ASC NULLS FIRST, start_at ASC`,
			issuer.ID,
		)
		if err != nil {
			c.Logger.Error("Failed to extract issuer keys from DB")
			return err
		}

		c.Logger.Debug("fetched the issuer keys")

		for _, v := range fetchIssuerKeys {
			issuer.Keys = append(issuer.Keys, v)
			c.Logger.Info("appended keys")
		}
		c.Logger.Info("txpopulateissuerkeys", "issuer keys", issuer.Keys)

		// populate the buffer of keys for the v3 issuer
		if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
			return fmt.Errorf("failed to close rows on v3 issuer creation: %w", err)
		}
		// denote that the v3 issuer was rotated at this time
		if _, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() where issuer_id = $1`,
			issuer.ID,
		); err != nil {
			return err
		}
	}

	return nil
}

// deleteIssuerKeys deletes v3 issuers keys that have ended more than the duration ago.
func (c *Server) deleteIssuerKeys(duration string) (int64, error) {
	result, err := c.db.Exec(`delete from v3_issuer_keys where issuer_id in (select issuer_id from v3_issuers where version = 3) and end_at < now() - $1::interval`, duration)
	if err != nil {
		return 0, fmt.Errorf("error deleting v3 issuer keys: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("error deleting v3 issuer keys row affected: %w", err)
	}

	return rows, nil
}

// createIssuer - creation of a v3 issuer
func (c *Server) createV3Issuer(issuer model.Issuer) (err error) {
	defer incrementTotal(createIssuerTotal)
	if issuer.MaxTokens == 0 {
		issuer.MaxTokens = 40
	}

	validFrom := issuer.ValidFrom
	if issuer.ValidFrom == nil {
		validFrom = ptr.FromTime(time.Now())
	}

	tx := c.db.MustBegin()
	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	queryTimer := prometheus.NewTimer(createTimeLimitedIssuerDBDuration)
	row := tx.QueryRowx(
		`
		INSERT INTO v3_issuers
			(
				issuer_type,
				issuer_cohort,
				max_tokens,
				version,
				expires_at,
				buffer,
				duration,
			 	overlap,
			 	valid_from)
		VALUES
		($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING issuer_id`,
		issuer.IssuerType,
		issuer.IssuerCohort,
		issuer.MaxTokens,
		issuer.Version,
		issuer.ExpiresAt,
		issuer.Buffer,
		issuer.Duration,
		issuer.Overlap,
		validFrom,
	)
	// get the newly inserted issuer identifier
	if err := row.Scan(&issuer.ID); err != nil {
		return fmt.Errorf("failed to get v3 issuer id: %w", err)
	}

	if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
		return fmt.Errorf("failed to close rows on v3 issuer creation: %w", err)
	}
	queryTimer.ObserveDuration()
	return nil
}

// on the transaction, populate v3 issuer keys for the v3 issuer
func txPopulateIssuerKeys(logger *slog.Logger, tx *sqlx.Tx, issuer model.Issuer) error {
	var (
		duration *timeutils.ISODuration
		err      error
	)

	logger.Debug("checking if v3")
	if issuer.Version == 3 {
		// get the duration from the issuer
		if issuer.Duration != nil {
			duration, err = timeutils.ParseDuration(*issuer.Duration)
			if err != nil {
				logger.Error(
					"failed to parse issuer duration",
					slog.Any("err", err),
				)
				return fmt.Errorf("failed to parse issuer duration: %w", err)
			}
		}
	}

	// v1/v2 issuers only have a buffer of 1
	if issuer.Version < 3 {
		issuer.Buffer = 1
	}

	var tmp time.Time
	if issuer.ValidFrom != nil {
		tmp = *issuer.ValidFrom
	}
	start := &tmp

	i := 0
	// time to create the keys associated with the issuer
	if issuer.Keys == nil || len(issuer.Keys) == 0 {
		issuer.Keys = []model.IssuerKeys{}
	} else {
		// if the issuer has keys already, start needs to be the last item in slice
		tmp := *issuer.Keys[len(issuer.Keys)-1].EndAt
		start = &tmp
		i = len(issuer.Keys)
		logger.Debug("figured out the lacking keys", "i", i, "start", start)
	}

	var keys []model.IssuerKeys
	for ; i < issuer.Buffer+issuer.Overlap; i++ {
		end := new(time.Time)
		if duration != nil {
			// start/end, increment every iteration
			end, err = duration.From(*start)
			if err != nil {
				logger.Error(
					"unable to calculate end time",
					slog.Any("err", err),
				)
				return fmt.Errorf("unable to calculate end time: %w", err)
			}
		}

		logger.Debug("txpopulateissuerkeys finished")

		signingKey, err := crypto.RandomSigningKey()
		if err != nil {
			logger.Error(
				"error generating key",
				slog.Any("err", err),
			)
			return err
		}

		signingKeyTxt, err := signingKey.MarshalText()
		if err != nil {
			logger.Error(
				"error marshalling signing key",
				slog.Any("err", err),
			)
			return err
		}

		pubKeyTxt, err := signingKey.PublicKey().MarshalText()
		if err != nil {
			logger.Error(
				"error marshalling public key",
				slog.Any("err", err),
			)
			return err
		}
		logger.Debug("iteration key", "pubkey", string(pubKeyTxt))

		tmpStart := *start
		tmpEnd := *end

		var k = model.IssuerKeys{
			SigningKey: signingKeyTxt,
			PublicKey:  ptr.FromString(string(pubKeyTxt)),
			Cohort:     issuer.IssuerCohort,
			IssuerID:   issuer.ID,
			StartAt:    &tmpStart,
			EndAt:      &tmpEnd,
		}

		keys = append(keys, k)

		// increment start
		tmp := *end
		start = &tmp
	}

	if len(keys) == 0 {
		// nothing to insert, return
		return nil
	}

	insertValues := make([]map[string]interface{}, len(keys))
	// create our value params for insertion
	for idx, v := range keys {
		insertValues[idx] =
			map[string]interface{}{"issuer_id": v.IssuerID, "signing_key": v.SigningKey, "public_key": v.PublicKey, "cohort": v.Cohort, "start_at": v.StartAt, "end_at": v.EndAt}
	}
	logger.Debug("txpopulateissuerkeys", "inserting", insertValues)

	_, err = tx.NamedExec(`INSERT INTO v3_issuer_keys (issuer_id, signing_key, public_key, cohort, start_at, end_at) 
		VALUES (:issuer_id, :signing_key, :public_key, :cohort, :start_at, :end_at)`, insertValues)
	if err != nil {
		logger.Error(
			"could not insert the new issuer keys into the db",
			slog.Any("err", err),
		)
		return err
	}
	logger.Debug("txpopulateissuerkeys", "performed insert", insertValues)
	return nil
}

func (c *Server) createIssuerV2(issuerType string, issuerCohort int16, maxTokens int, expiresAt *time.Time) error {
	defer incrementTotal(createIssuerTotal)
	if maxTokens == 0 {
		maxTokens = 40
	}

	// convert to a v3 issuer
	return c.createV3Issuer(model.Issuer{
		IssuerType:   issuerType,
		IssuerCohort: issuerCohort,
		Version:      2,
		MaxTokens:    maxTokens,
		ExpiresAt:    pq.NullTime{Time: *expiresAt, Valid: expiresAt != nil},
	})
}

func (c *Server) createIssuer(issuerType string, issuerCohort int16, maxTokens int, expiresAt *time.Time) error {
	defer incrementTotal(createIssuerTotal)
	if maxTokens == 0 {
		maxTokens = 40
	}

	// convert to a v3 issuer
	return c.createV3Issuer(model.Issuer{
		IssuerType:   issuerType,
		IssuerCohort: issuerCohort,
		Version:      1,
		MaxTokens:    maxTokens,
		ExpiresAt:    pq.NullTime{Time: *expiresAt, Valid: expiresAt != nil},
	})
}

// Queryable is an interface requiring the method Query
type Queryable interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// RedeemToken redeems a token given an issuer and and preimage
func (c *Server) RedeemToken(issuerForRedemption *model.Issuer, preimage *crypto.TokenPreimage, payload string, offset int64) error {
	defer incrementTotal(redeemTokenTotal)
	if issuerForRedemption.Version == 1 {
		return redeemTokenWithDB(c.db, issuerForRedemption.IssuerType, preimage, payload)
	} else if issuerForRedemption.Version == 2 || issuerForRedemption.Version == 3 {
		return c.redeemTokenWithDynamo(issuerForRedemption, preimage, payload, offset)
	}
	return errors.New("wrong issuer version")
}

func redeemTokenWithDB(db Queryable, stringIssuer string, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	queryTimer := prometheus.NewTimer(createRedemptionDBDuration)
	rows, err := db.Query(
		`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, stringIssuer, payload)
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

func (c *Server) fetchRedemption(issuerType, id string) (*Redemption, error) {
	defer incrementTotal(fetchRedemptionTotal)

	if cached := retrieveFromCache(c.caches, "redemptions", fmt.Sprintf("%s:%s", issuerType, id)); cached != nil {
		if redemption, ok := cached.(*Redemption); ok {
			return redemption, nil
		}
	}

	queryTimer := prometheus.NewTimer(fetchRedemptionDBDuration)
	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions WHERE id = $1 AND issuer_type = $2`, id, issuerType)
	queryTimer.ObserveDuration()

	if err != nil {
		c.Logger.Error("Unable to perform the query")
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var redemption = Redemption{}
		if err := rows.Scan(&redemption.ID, &redemption.IssuerType, &redemption.Timestamp, &redemption.Payload); err != nil {
			c.Logger.Error("Unable to convert DB values into redemption data structure")
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerType, id), &redemption)
		}

		return &redemption, nil
	}

	if err := rows.Err(); err != nil {
		c.Logger.Error("Error parsing rows of DB")
		return nil, err
	}

	c.Logger.Error("Redemption not found")
	return nil, errRedemptionNotFound
}

// isPostgresNotFoundError uses the error map found at the below URL to determine if an
// error is a Postgres no_data_found error.
// https://github.com/lib/pq/blob/d5affd5073b06f745459768de35356df2e5fd91d/error.go#L348
func isPostgresNotFoundError(err error) bool {
	pqError, ok := err.(*pq.Error)
	if !ok {
		return false
	}
	if pqError.Code.Class().Name() != "no_data_found" {
		return true
	}
	return false
}

func retrieveFromCache(
	caches map[string]CacheInterface,
	cacheName string,
	key string,
) interface{} {
	if caches != nil {
		if cached, found := caches[cacheName].Get(key); found {
			return cached
		}
	}
	return nil
}

func bootstrapCache(cfg DBConfig) map[string]CacheInterface {
	caches := make(map[string]CacheInterface)
	defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
	caches["issuers"] = cache.New(defaultDuration, 2*defaultDuration)
	caches["issuer"] = cache.New(defaultDuration, 2*defaultDuration)
	caches["redemptions"] = cache.New(defaultDuration, 2*defaultDuration)
	caches["issuercohort"] = cache.New(defaultDuration, 2*defaultDuration)
	return caches
}
