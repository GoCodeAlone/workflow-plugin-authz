package internal

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestStorageMigrationModelsPreserveDialectWidths(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		dialect string
		width   int
	}{
		{dialect: "postgres", width: 512},
		{dialect: "mysql", width: 512},
		{dialect: "sqlite", width: 512},
	} {
		t.Run(tt.dialect, func(t *testing.T) {
			t.Parallel()
			parsed, err := schema.Parse(storageMigrationModel(tt.dialect), &sync.Map{}, schema.NamingStrategy{})
			if err != nil {
				t.Fatalf("parse %s migration model: %v", tt.dialect, err)
			}
			if got := int(parsed.LookUpField("Ptype").Size); got != tt.width {
				t.Fatalf("%s migration width = %d, want %d", tt.dialect, got, tt.width)
			}
		})
	}
}

func TestStoragePostgresCatalogQueryIncludesExactIndexMetadata(t *testing.T) {
	t.Parallel()

	for _, required := range []string{
		"pg_catalog.pg_index",
		"indisprimary",
		"indisunique",
		"indpred",
		"pg_get_expr",
		"WITH ORDINALITY",
		"ordinality",
		"ORDER BY",
	} {
		if !strings.Contains(postgresStorageIndexesSQL, required) {
			t.Errorf("PostgreSQL index catalog query is missing %q", required)
		}
	}
	for _, excluded := range []string{"contype <> 'p'", "constraint_oid IS NULL", "con.oid IS NULL"} {
		if strings.Contains(postgresStorageIndexesSQL, excluded) {
			t.Errorf("PostgreSQL index catalog query excludes constraint indexes with %q", excluded)
		}
	}
}

func TestStoragePostgresCatalogRowsPreserveColumnsAndPredicates(t *testing.T) {
	t.Parallel()

	rows := []postgresStorageIndexRow{
		{IndexName: "authz_policy_pkey", Primary: true, Unique: true, ColumnName: "id", Ordinal: 1},
		{IndexName: "uidx_authz_policy", Unique: true, ColumnName: "ptype", Ordinal: 1},
		{IndexName: "uidx_authz_policy", Unique: true, ColumnName: "v0", Ordinal: 2},
		{IndexName: "uidx_constraint", Unique: true, ColumnName: "v1", Ordinal: 1},
		{IndexName: "uidx_partial", Unique: true, Predicate: "(v2 <> ''::text)", ColumnName: "v2", Ordinal: 1},
	}

	got, err := mapPostgresStorageIndexes("authz_policy", rows)
	if err != nil {
		t.Fatalf("mapPostgresStorageIndexes(): %v", err)
	}
	want := []storageIndexMetadata{
		{Table: "authz_policy", Name: "authz_policy_pkey", Columns: []string{"id"}, Primary: true, Unique: true},
		{Table: "authz_policy", Name: "uidx_authz_policy", Columns: []string{"ptype", "v0"}, Unique: true},
		{Table: "authz_policy", Name: "uidx_constraint", Columns: []string{"v1"}, Unique: true},
		{Table: "authz_policy", Name: "uidx_partial", Columns: []string{"v2"}, Unique: true, Predicate: "(v2 <> ''::text)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapPostgresStorageIndexes() =\n%#v\nwant\n%#v", got, want)
	}
}

func TestStoragePostgresPredicateFailsExactValidation(t *testing.T) {
	t.Parallel()

	descriptor, err := StorageSchemaForDialect(StorageDialectPostgres, "authz_policy")
	if err != nil {
		t.Fatalf("StorageSchemaForDialect(): %v", err)
	}
	rows := make([]postgresStorageIndexRow, 0, len(descriptor.UniqueIndexes[0].Columns))
	for i, column := range descriptor.UniqueIndexes[0].Columns {
		rows = append(rows, postgresStorageIndexRow{
			IndexName:  descriptor.UniqueIndexes[0].Name,
			Unique:     true,
			Predicate:  "(v0 <> ''::character varying)",
			ColumnName: column,
			Ordinal:    i + 1,
		})
	}
	metadata, err := mapPostgresStorageIndexes(descriptor.Table, rows)
	if err != nil {
		t.Fatalf("mapPostgresStorageIndexes(): %v", err)
	}
	const want = "authz storage schema v1 unique index"
	if err := validateStorageIndexes(storageIndexesFromMetadata(metadata), descriptor); err == nil || err.Error() != want {
		t.Fatalf("validateStorageIndexes() error = %v, want exactly %q", err, want)
	}
}
