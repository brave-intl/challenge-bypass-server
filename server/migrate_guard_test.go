//go:build db

package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/stretchr/testify/require"
)

// An older image (whose migration files stop before the DB's version) must
// start cleanly instead of panicking: that is what makes rollback safe.
func TestMigrateSchemaSkipsWhenDBAhead(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.InitDBConfig())
	srv.InitDB(slog.New(slog.DiscardHandler)) // DB now at schemaVersion

	// Simulate the previous release: migrations up to schemaVersion-1 only.
	older := t.TempDir()
	files, err := os.ReadDir("/src/migrations")
	require.NoError(t, err)
	for _, f := range files {
		head, _, _ := strings.Cut(f.Name(), "_")
		v, err := strconv.ParseUint(head, 10, 32)
		if err != nil || uint(v) >= schemaVersion {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/src/migrations", f.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(older, f.Name()), b, 0o600))
	}

	driver, err := postgres.WithInstance(srv.db, &postgres.Config{})
	require.NoError(t, err)
	m, err := migrate.NewWithDatabaseInstance("file://"+older, "postgres", driver)
	require.NoError(t, err)

	require.NoError(t, migrateSchema(m, schemaVersion-1, slog.New(slog.DiscardHandler)))

	v, dirty, err := m.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, schemaVersion, v, "must never migrate down")
}
