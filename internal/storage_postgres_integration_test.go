package internal

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestStoragePostgresIntegrationConstraintAndPredicate(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_POSTGRES_DSN is not set")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get PostgreSQL connection: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	table := fmt.Sprintf("authz_contract_%d", time.Now().UnixNano())
	index := "uidx_" + table
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + table).Error })
	execPostgresFixtureSQL(t, db, fmt.Sprintf(`CREATE TABLE %s (
		id bigserial PRIMARY KEY,
		ptype varchar(512) NOT NULL,
		v0 varchar(512) NOT NULL,
		v1 varchar(512) NOT NULL,
		v2 varchar(512) NOT NULL,
		v3 varchar(512) NOT NULL,
		v4 varchar(512) NOT NULL,
		v5 varchar(512) NOT NULL,
		CONSTRAINT %s UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
	)`, table, index))

	if err := ValidateStorage(t.Context(), db, table); err != nil {
		t.Fatalf("ValidateStorage() with constraint-backed index: %v", err)
	}

	execPostgresFixtureSQL(t, db, "ALTER TABLE "+table+" DROP CONSTRAINT "+index)
	execPostgresFixtureSQL(t, db, fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (ptype, v0, v1, v2, v3, v4, v5) WHERE v0 <> ''", index, table))
	const want = "authz storage schema v1 unique index"
	if err := ValidateStorage(t.Context(), db, table); err == nil || err.Error() != want {
		t.Fatalf("ValidateStorage() partial-index error = %v, want exactly %q", err, want)
	}
}

func execPostgresFixtureSQL(t *testing.T, db *gorm.DB, query string) {
	t.Helper()
	if err := db.Exec(query).Error; err != nil {
		t.Fatalf("execute PostgreSQL fixture SQL: %v", err)
	}
}
