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
	"github.com/google/uuid"

	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"

	timeutils "github.com/brave-intl/bat-go/libs/time"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

// DBConfig defines app configurations
type DBConfig struct {
	ConnectionURI           string        `json:"connectionURI"`
	ConnectionURIReader     string        `json:"connectionURIReader"`
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

var (
	errIssuerNotFound       = errors.New("issuer with the given name does not exist")
	errIssuerCohortNotFound = errors.New("issuer with the given name and cohort does not exist")
	errDuplicateRedemption  = errors.New("duplicate Redemption")
	errRedemptionNotFound   = errors.New("redemption with the given id does not exist")
)

const issuerColumns = `issuer_id, issuer_type, created_at, expires_at, last_rotated_at,
                       valid_from, buffer, days_out, overlap, issuer_cohort,
                       redemption_repository, version, max_tokens, duration`

// LoadDBConfig loads config into server variable
func (c *Server) LoadDBConfig(config DBConfig) {
	c.dbConfig = config
}

func makeDBConnection(uri string, maxConnection int) (*sql.DB, error) {
	db, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(maxConnection)
	db.SetMaxIdleConns(maxConnection / 2)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(90 * time.Second)

	return db, nil
}

// InitDB initialzes the database connection based on a server's configuration
func (c *Server) InitDB(logger *slog.Logger) {
	cfg := c.dbConfig

	writer, err := makeDBConnection(cfg.ConnectionURI, cfg.MaxConnection)
	if err != nil {
		panic(err)
	}

	var reader *sql.DB
	if cfg.ConnectionURIReader != "" {
		reader, err = makeDBConnection(cfg.ConnectionURIReader, cfg.MaxConnection)
		if err != nil {
			logger.Warn("database reader instance not connected", "error", err)
		}
	}

	c.db = writer
	// Use the writer for the reader as well if the reader connection is missing
	if reader != nil {
		c.dbr = reader
	} else {
		c.dbr = writer
	}

	// Database Telemetry
	collector := metrics.NewStatsCollector("challenge_bypass_db", writer)
	err = prometheus.Register(collector)
	if ae, ok := err.(prometheus.AlreadyRegisteredError); ok {
		if sc, ok := ae.ExistingCollector.(*metrics.StatsCollector); ok {
			sc.AddStatsGetter("challenge_bypass_db", writer)
		}
	}

	if os.Getenv("ENV") != "production" {
		time.Sleep(10 * time.Second)
	}

	driver, err := postgres.WithInstance(writer, &postgres.Config{})
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

	issuer, ok := retrieveFromCache[*model.Issuer](c.caches, "issuer", issuerID)
	if ok {
		return issuer, nil
	}

	query := fmt.Sprintf(`SELECT %s FROM v3_issuers WHERE issuer_id=$1`, issuerColumns)

	row := c.dbr.QueryRow(query, issuerID)

	var fetchedIssuer model.Issuer
	err := scanIssuer(row, &fetchedIssuer)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ProcessingErrorFromError(errIssuerNotFound, false)
		}
		return nil, utils.ProcessingErrorFromError(err, true)
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

// Helper function to scan issuer from QueryRow
func scanIssuer(row *sql.Row, issuer *model.Issuer) error {
	var issuerID sql.NullString
	var redemptionRepository sql.NullString
	var daysOut sql.NullInt32

	err := row.Scan(
		&issuerID,
		&issuer.IssuerType,
		&issuer.CreatedAt,
		&issuer.ExpiresAt,
		&issuer.RotatedAt,
		&issuer.ValidFrom,
		&issuer.Buffer,
		&daysOut,
		&issuer.Overlap,
		&issuer.IssuerCohort,
		&redemptionRepository,
		&issuer.Version,
		&issuer.MaxTokens,
		&issuer.Duration,
	)

	if err != nil {
		return err
	}

	if issuerID.Valid {
		id, err := uuid.Parse(issuerID.String)
		if err != nil {
			return err
		}
		issuer.ID = &id
	}

	if daysOut.Valid {
		issuer.DaysOut = int(daysOut.Int32)
	}

	if redemptionRepository.Valid {
		issuer.RedemptionRepository = redemptionRepository.String
	}

	return nil
}

// Helper for scanning from Rows
func scanIssuerFromRows(rows *sql.Rows, issuer *model.Issuer) error {
	var issuerID sql.NullString
	var redemptionRepository sql.NullString
	var daysOut sql.NullInt32

	err := rows.Scan(
		&issuerID,
		&issuer.IssuerType,
		&issuer.CreatedAt,
		&issuer.ExpiresAt,
		&issuer.RotatedAt,
		&issuer.ValidFrom,
		&issuer.Buffer,
		&daysOut,
		&issuer.Overlap,
		&issuer.IssuerCohort,
		&redemptionRepository,
		&issuer.Version,
		&issuer.MaxTokens,
		&issuer.Duration,
	)

	if err != nil {
		return err
	}

	if issuerID.Valid {
		id, err := uuid.Parse(issuerID.String)
		if err != nil {
			return err
		}
		issuer.ID = &id
	}

	if daysOut.Valid {
		issuer.DaysOut = int(daysOut.Int32)
	}

	if redemptionRepository.Valid {
		issuer.RedemptionRepository = redemptionRepository.String
	}

	return nil
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
	issuers, ok := retrieveFromCache[[]model.Issuer](c.caches, "issuercohort", issuerType)
	if ok {
		return issuers, nil
	}

	rows, err := c.dbr.Query(queryTemplate, issuerType, issuerCohort)
	if err != nil {
		c.Logger.Error("Failed to extract issuers from DB")
		return nil, utils.ProcessingErrorFromError(err, true)
	}
	defer rows.Close()

	var fetchedIssuers []model.Issuer
	for rows.Next() {
		var issuer model.Issuer
		err := scanIssuerFromRows(rows, &issuer)
		if err != nil {
			return nil, err
		}
		fetchedIssuers = append(fetchedIssuers, issuer)
	}

	if err = rows.Err(); err != nil {
		return nil, err
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
	issuer, ok := retrieveFromCache[*model.Issuer](c.caches, "issuer", issuerType)
	if ok {
		return issuer, nil
	}

	query := fmt.Sprintf(`SELECT %s FROM v3_issuers
              WHERE issuer_type=$1
              ORDER BY expires_at DESC NULLS LAST, created_at DESC
              LIMIT 1`, issuerColumns)

	row := c.dbr.QueryRowContext(ctx, query, issuerType)

	var issuerV3 model.Issuer
	err := scanIssuer(row, &issuerV3)
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
	issuers, ok := retrieveFromCache[[]model.Issuer](c.caches, "issuers", "all")
	if ok {
		return issuers, nil
	}

	query := fmt.Sprintf(`SELECT %s FROM v3_issuers 
              ORDER BY expires_at DESC NULLS LAST, created_at DESC`, issuerColumns)

	rows, err := c.dbr.Query(query)
	if err != nil {
		c.Logger.Error("Failed to extract issuers from DB")
		return nil, utils.ProcessingErrorFromError(err, true)
	}
	defer rows.Close()

	var fetchedIssuers []model.Issuer
	for rows.Next() {
		var issuer model.Issuer
		err := scanIssuerFromRows(rows, &issuer)
		if err != nil {
			return nil, err
		}
		fetchedIssuers = append(fetchedIssuers, issuer)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	results := make([]model.Issuer, len(fetchedIssuers))
	for idx, currIssuer := range fetchedIssuers {
		var issuerIDStr string
		if currIssuer.ID != nil {
			issuerIDStr = currIssuer.ID.String()
		}

		keys, err := c.fetchIssuerKeysForIssuer(issuerIDStr)
		if err != nil {
			return nil, err
		}
		currIssuer.Keys = keys
		results[idx] = currIssuer
	}

	if c.caches != nil {
		c.caches["issuers"].SetDefault("all", results)
	}

	return results, nil
}

func (c *Server) fetchIssuerKeysForIssuer(issuerID string) ([]model.IssuerKeys, error) {
	query := `SELECT signing_key, public_key, cohort, issuer_id, start_at, end_at, created_at
              FROM v3_issuer_keys 
              WHERE issuer_id=$1
                AND (end_at > now() OR end_at IS NULL) 
                AND (start_at <= now() OR start_at IS NULL)
              ORDER BY end_at ASC NULLS LAST, start_at ASC, created_at ASC`

	rows, err := c.dbr.Query(query, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []model.IssuerKeys
	for rows.Next() {
		var key model.IssuerKeys
		var publicKey sql.NullString
		var issuerIDStr sql.NullString

		err := rows.Scan(
			&key.SigningKey,
			&publicKey,
			&key.Cohort,
			&issuerIDStr,
			&key.StartAt,
			&key.EndAt,
			&key.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if publicKey.Valid {
			key.PublicKey = &publicKey.String
		}

		if issuerIDStr.Valid {
			id, err := uuid.Parse(issuerIDStr.String)
			if err != nil {
				return nil, err
			}
			key.IssuerID = &id
		}

		keys = append(keys, key)
	}

	return keys, rows.Err()
}

func (c *Server) fetchIssuerKeys(fetchedIssuers []model.Issuer) ([]model.Issuer, error) {
	var issuers []model.Issuer

	for _, fetchedIssuer := range fetchedIssuers {
		lteVersionTwo := fetchedIssuer.Version <= 2

		var issuerIDStr string
		if fetchedIssuer.ID != nil {
			issuerIDStr = fetchedIssuer.ID.String()
		}

		query := `SELECT signing_key, public_key, cohort, issuer_id, start_at, end_at, created_at
                  FROM v3_issuer_keys 
                  WHERE issuer_id=$1
                    AND ($2 OR end_at > now())
                  ORDER BY end_at ASC NULLS FIRST, start_at ASC`

		rows, err := c.dbr.Query(query, issuerIDStr, lteVersionTwo)
		if err != nil {
			isNotPostgresNotFoundError := !isPostgresNotFoundError(err)
			if isNotPostgresNotFoundError {
				c.Logger.Error("Issuer key was not found in DB")
			}
			return nil, utils.ProcessingErrorFromError(err, isNotPostgresNotFoundError)
		}

		var keys []model.IssuerKeys
		for rows.Next() {
			var key model.IssuerKeys
			var publicKey sql.NullString
			var issuerIDStr sql.NullString

			err := rows.Scan(
				&key.SigningKey,
				&publicKey,
				&key.Cohort,
				&issuerIDStr,
				&key.StartAt,
				&key.EndAt,
				&key.CreatedAt,
			)
			if err != nil {
				rows.Close() //nolint:sqlclosecheck // Intentionally not using defer in loop
				return nil, err
			}

			if publicKey.Valid {
				key.PublicKey = &publicKey.String
			}

			if issuerIDStr.Valid {
				id, err := uuid.Parse(issuerIDStr.String)
				if err != nil {
					rows.Close() //nolint:sqlclosecheck // Intentionally not using defer in loop
					return nil, err
				}
				key.IssuerID = &id
			}

			keys = append(keys, key)
		}

		err = rows.Err()
		rows.Close()

		if err != nil {
			return nil, err
		}

		fetchedIssuer.Keys = append(fetchedIssuer.Keys, keys...)
		issuers = append(issuers, fetchedIssuer)
	}

	return issuers, nil
}

// RotateIssuers is the function that rotates
func (c *Server) rotateIssuers() error {
	cfg := c.dbConfig

	tx, err := c.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	query := fmt.Sprintf(`SELECT %s FROM v3_issuers
              WHERE expires_at IS NOT NULL
              AND last_rotated_at < NOW() - $1 * INTERVAL '1 day'
              AND expires_at < NOW() + $1 * INTERVAL '1 day'
              AND version <= 2
              FOR UPDATE SKIP LOCKED`, issuerColumns)

	rows, err := tx.Query(query, cfg.DefaultDaysBeforeExpiry)
	if err != nil {
		return err
	}
	defer rows.Close()

	var fetchedIssuers []model.Issuer
	for rows.Next() {
		var issuer model.Issuer
		err := scanIssuerFromRows(rows, &issuer)
		if err != nil {
			return err
		}
		fetchedIssuers = append(fetchedIssuers, issuer)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	for _, v := range fetchedIssuers {
		if err := txPopulateIssuerKeys(c.Logger, tx, v); err != nil {
			return fmt.Errorf("failed to populate v3 issuer keys: %w", err)
		}

		var issuerIDStr string
		if v.ID != nil {
			issuerIDStr = v.ID.String()
		}

		_, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() WHERE issuer_id = $1`,
			issuerIDStr,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// RotateIssuersV3 is the function that rotates time aware issuers
func (c *Server) RotateIssuersV3() error {
	return c.rotateIssuersV3()
}

// RotateIssuers is the function that rotates issuer version 1 and 2 (where supported)
func (c *Server) RotateIssuers() error {
	return c.rotateIssuers()
}

// DeleteIssuerKeys deletes v3 issuers keys that have ended more than the duration ago.
func (c *Server) DeleteIssuerKeys(duration string) (int64, error) {
	return c.deleteIssuerKeys(duration)
}

// rotateIssuersV3 is the function implementation that rotates time aware issuers
func (c *Server) rotateIssuersV3() error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	// we need to get all the v3 issuers that are
	// 1. not expired
	// 2. now is after valid_from
	// 3. have max(issuer_v3.end_at) < buffer
	// Use column names without alias prefix since we're selecting from a single table
	query := fmt.Sprintf(`
        SELECT %s
        FROM v3_issuers
        WHERE version = 3 
          AND expires_at IS NOT NULL 
          AND expires_at > now() 
          AND (SELECT max(end_at) FROM v3_issuer_keys WHERE issuer_id=v3_issuers.issuer_id) < now()
                + buffer * duration::interval
                + overlap * duration::interval - 1 * duration::interval
        FOR UPDATE SKIP LOCKED`, issuerColumns)

	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var fetchedIssuers []model.Issuer
	for rows.Next() {
		var issuer model.Issuer
		err := scanIssuerFromRows(rows, &issuer)
		if err != nil {
			return err
		}
		fetchedIssuers = append(fetchedIssuers, issuer)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	for _, issuer := range fetchedIssuers {
		var issuerIDStr string
		if issuer.ID != nil {
			issuerIDStr = issuer.ID.String()
		}

		keyQuery := `SELECT signing_key, public_key, cohort, issuer_id, start_at, end_at, created_at
                     FROM v3_issuer_keys 
                     WHERE issuer_id=$1 AND end_at > now()
                     ORDER BY end_at ASC NULLS FIRST, start_at ASC`

		keyRows, err := tx.Query(keyQuery, issuerIDStr)
		if err != nil {
			c.Logger.Error("Failed to extract issuer keys from DB")
			return err
		}

		var fetchIssuerKeys []model.IssuerKeys
		for keyRows.Next() {
			var key model.IssuerKeys
			var publicKey sql.NullString
			var keyIssuerIDStr sql.NullString

			err := keyRows.Scan(
				&key.SigningKey,
				&publicKey,
				&key.Cohort,
				&keyIssuerIDStr,
				&key.StartAt,
				&key.EndAt,
				&key.CreatedAt,
			)
			if err != nil {
				keyRows.Close() //nolint:sqlclosecheck // Intentionally not using defer in loop
				return err
			}

			if publicKey.Valid {
				key.PublicKey = &publicKey.String
			}

			if keyIssuerIDStr.Valid {
				id, err := uuid.Parse(keyIssuerIDStr.String)
				if err != nil {
					keyRows.Close() //nolint:sqlclosecheck // Intentionally not using defer in loop
					return err
				}
				key.IssuerID = &id
			}

			fetchIssuerKeys = append(fetchIssuerKeys, key)
		}

		err = keyRows.Err()
		keyRows.Close()

		if err != nil {
			return err
		}

		c.Logger.Debug("fetched the issuer keys")
		for _, v := range fetchIssuerKeys {
			issuer.Keys = append(issuer.Keys, v)
			c.Logger.Info("appended keys")
		}

		c.Logger.Info("txpopulateissuerkeys", "issuer keys", issuer.Keys)

		if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
			return fmt.Errorf("failed to populate v3 issuer keys: %w", err)
		}

		_, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() WHERE issuer_id = $1`,
			issuerIDStr,
		)
		if err != nil {
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

	tx, err := c.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	queryTimer := prometheus.NewTimer(createTimeLimitedIssuerDBDuration)

	var issuerIDStr string
	err = tx.QueryRow(`
        INSERT INTO v3_issuers
            (issuer_type, issuer_cohort, max_tokens, version, expires_at,
             buffer, duration, overlap, valid_from)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
	).Scan(&issuerIDStr)

	if err != nil {
		return fmt.Errorf("failed to get v3 issuer id: %w", err)
	}

	id, err := uuid.Parse(issuerIDStr)
	if err != nil {
		return fmt.Errorf("failed to parse issuer id: %w", err)
	}
	issuer.ID = &id

	if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
		return fmt.Errorf("failed to populate v3 issuer keys: %w", err)
	}

	queryTimer.ObserveDuration()
	return nil
}

// on the transaction, populate v3 issuer keys for the v3 issuer
func txPopulateIssuerKeys(logger *slog.Logger, tx *sql.Tx, issuer model.Issuer) error {
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

	// Prepare the insert statement
	stmt, err := tx.Prepare(`
            INSERT INTO v3_issuer_keys (issuer_id, signing_key, public_key, cohort, start_at, end_at) 
            VALUES ($1, $2, $3, $4, $5, $6)
        `)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, key := range keys {
		var keyIssuerIDStr string
		if key.IssuerID != nil {
			keyIssuerIDStr = key.IssuerID.String()
		}
		_, err = stmt.Exec(
			keyIssuerIDStr,
			key.SigningKey,
			*key.PublicKey,
			key.Cohort,
			key.StartAt,
			key.EndAt,
		)
		if err != nil {
			logger.Error(
				"could not insert the new issuer keys into the db",
				slog.Any("err", err),
			)
			return err
		}
	}

	logger.Debug("txpopulateissuerkeys", "performed insert", len(keys))
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
	Query(query string, args ...any) (*sql.Rows, error)
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

	redemption, ok := retrieveFromCache[*Redemption](c.caches, "redemptions", fmt.Sprintf("%s:%s", issuerType, id))
	if ok {
		return redemption, nil
	}

	queryTimer := prometheus.NewTimer(fetchRedemptionDBDuration)
	rows, err := c.dbr.Query(
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
