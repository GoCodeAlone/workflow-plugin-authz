package internal

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestStoragePostgresIntegrationContract(t *testing.T) {
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
	descriptor, err := StorageSchemaForDialect(StorageDialectPostgres, table)
	if err != nil {
		t.Fatalf("PostgreSQL descriptor: %v", err)
	}
	valueType := descriptor.Columns[1].Type
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + table).Error })
	execPostgresFixtureSQL(t, db, fmt.Sprintf(`CREATE TABLE %s (
		id bigserial PRIMARY KEY,
		ptype %s NOT NULL,
		v0 %s NOT NULL,
		v1 %s NOT NULL,
		v2 %s NOT NULL,
		v3 %s NOT NULL,
		v4 %s NOT NULL,
		v5 %s NOT NULL,
		CONSTRAINT %s UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
	)`, table, valueType, valueType, valueType, valueType, valueType, valueType, valueType, index))

	if err := ValidateStorage(t.Context(), db, table); err != nil {
		t.Fatalf("ValidateStorage() with constraint-backed index: %v", err)
	}
	width := postgresDescriptorWidth(t, valueType)
	values := make([]any, 7)
	for i := range values {
		values[i] = incompressibleFourByteUTF8(t, width)
	}
	if err := db.Exec("INSERT INTO "+table+" (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", values...).Error; err != nil {
		t.Fatalf("insert seven maximum-width descriptor values: %v", err)
	}
	overLimitValues := []any{
		incompressibleFourByteUTF8(t, width+1),
		"safe-v0", "safe-v1", "safe-v2", "safe-v3", "safe-v4", "safe-v5",
	}
	overLimitErr := db.Exec("INSERT INTO "+table+" (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", overLimitValues...).Error
	if overLimitErr == nil {
		t.Fatal("PostgreSQL accepted a row above the published character/octet boundary")
	}
	execPostgresFixtureSQL(t, db, "ALTER TABLE "+table+" DROP CONSTRAINT "+index)
	execPostgresFixtureSQL(t, db, fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (ptype, v0, v1, v2, v3, v4, v5) WHERE v0 <> ''", index, table))
	const want = "authz storage schema v1 unique index"
	if err := ValidateStorage(t.Context(), db, table); err == nil || err.Error() != want {
		t.Fatalf("ValidateStorage() partial-index error = %v, want exactly %q", err, want)
	}

	overLimitTable := fmt.Sprintf("authz_over_%d", time.Now().UnixNano())
	overLimitIndex := "uidx_" + overLimitTable
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + overLimitTable).Error })
	overLimitType := fmt.Sprintf("varchar(%d)", width+1)
	execPostgresFixtureSQL(t, db, fmt.Sprintf(`CREATE TABLE %s (
		id bigserial PRIMARY KEY,
		ptype %s NOT NULL,
		v0 %s NOT NULL,
		v1 %s NOT NULL,
		v2 %s NOT NULL,
		v3 %s NOT NULL,
		v4 %s NOT NULL,
		v5 %s NOT NULL,
		CONSTRAINT %s UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
	)`, overLimitTable, overLimitType, overLimitType, overLimitType, overLimitType, overLimitType, overLimitType, overLimitType, overLimitIndex))
	const typesWant = "authz storage schema v1 types"
	if err := ValidateStorage(t.Context(), db, overLimitTable); err == nil || err.Error() != typesWant {
		t.Fatalf("ValidateStorage() over-limit schema error = %v, want exactly %q", err, typesWant)
	}

	autoTable := fmt.Sprintf("authz_auto_%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + autoTable).Error })
	if _, err := newGORMAdapter(db, autoTable, "", "", MigrationModeAuto); err != nil {
		t.Fatalf("newGORMAdapter(auto): %v", err)
	}
	assertPostgresColumnWidth(t, db, autoTable, "ptype", 512)
	if err := db.Exec("INSERT INTO "+autoTable+" (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, '', '', '', '', '', '')", strings.Repeat("x", 81)).Error; err != nil {
		t.Fatalf("legacy auto schema rejected an 81-character policy value: %v", err)
	}
	if err := ValidateStorage(t.Context(), db, autoTable); err == nil || err.Error() != typesWant {
		t.Fatalf("strict validation of legacy auto schema error = %v, want exactly %q", err, typesWant)
	}

	legacyTable := fmt.Sprintf("authz_legacy_%d", time.Now().UnixNano())
	legacyIndex := "uidx_" + legacyTable
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + legacyTable).Error })
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
	)`, legacyTable, legacyIndex))
	longValue := strings.Repeat("z", 81)
	if err := db.Exec("INSERT INTO "+legacyTable+" (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, '', '', '', '', '', '')", longValue).Error; err != nil {
		t.Fatalf("seed legacy auto schema: %v", err)
	}
	if _, err := newGORMAdapter(db, legacyTable, "", "", MigrationModeAuto); err != nil {
		t.Fatalf("newGORMAdapter(existing legacy auto): %v", err)
	}
	assertPostgresColumnWidth(t, db, legacyTable, "ptype", 512)
	var legacyCount int64
	if err := db.Table(legacyTable).Where("ptype = ?", longValue).Count(&legacyCount).Error; err != nil || legacyCount != 1 {
		t.Fatalf("legacy value after auto migration count=%d error=%v, want 1", legacyCount, err)
	}
}

func assertPostgresColumnWidth(t *testing.T, db *gorm.DB, table, column string, want int) {
	t.Helper()
	var got int
	if err := db.Raw(`SELECT character_maximum_length
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`, table, column).Scan(&got).Error; err != nil {
		t.Fatalf("inspect %s.%s width: %v", table, column, err)
	}
	if got != want {
		t.Fatalf("%s.%s width = %d, want legacy auto width %d", table, column, got, want)
	}
}

func postgresDescriptorWidth(t *testing.T, valueType string) int {
	t.Helper()
	value := strings.TrimSuffix(strings.TrimPrefix(valueType, "varchar("), ")")
	width, err := strconv.Atoi(value)
	if err != nil || width < 1 {
		t.Fatalf("parse PostgreSQL descriptor width %q", valueType)
	}
	return width
}

func incompressibleFourByteUTF8(t *testing.T, length int) string {
	t.Helper()
	raw := make([]byte, length*4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate random fixture: %v", err)
	}
	var value strings.Builder
	value.Grow(length * 4)
	for i := range length {
		codePoint := rune(0x10000 + binary.BigEndian.Uint32(raw[i*4:(i+1)*4])%0x100000)
		value.WriteRune(codePoint)
	}
	result := value.String()
	if utf8.RuneCountInString(result) != length || len(result) != length*4 {
		t.Fatalf("worst-case UTF-8 fixture has runes=%d octets=%d, want runes=%d octets=%d", utf8.RuneCountInString(result), len(result), length, length*4)
	}
	return result
}

func execPostgresFixtureSQL(t *testing.T, db *gorm.DB, query string) {
	t.Helper()
	if err := db.Exec(query).Error; err != nil {
		t.Fatalf("execute PostgreSQL fixture SQL: %v", err)
	}
}
