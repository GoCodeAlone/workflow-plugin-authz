package authz

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"
)

const (
	// StorageSchemaVersion identifies the published persistent policy schema.
	StorageSchemaVersion = 1

	defaultStorageTable = "casbin_rule"
)

// StorageColumn describes one required policy storage column.
type StorageColumn struct {
	Name     string
	Type     string
	Nullable bool
}

// StorageIndex describes one required policy storage index.
type StorageIndex struct {
	Name    string
	Columns []string
}

// StorageDescriptor is the complete public policy storage contract.
type StorageDescriptor struct {
	Version       int
	Table         string
	Columns       []StorageColumn
	PrimaryKey    []string
	UniqueIndexes []StorageIndex
}

// StorageSchema returns the published schema descriptor for tableName. An empty
// table name selects the adapter's default table.
func StorageSchema(tableName string) StorageDescriptor {
	if tableName == "" {
		tableName = defaultStorageTable
	}
	return StorageDescriptor{
		Version: StorageSchemaVersion,
		Table:   tableName,
		Columns: []StorageColumn{
			{Name: "id", Type: "bigint", Nullable: false},
			{Name: "ptype", Type: "varchar(512)", Nullable: false},
			{Name: "v0", Type: "varchar(512)", Nullable: false},
			{Name: "v1", Type: "varchar(512)", Nullable: false},
			{Name: "v2", Type: "varchar(512)", Nullable: false},
			{Name: "v3", Type: "varchar(512)", Nullable: false},
			{Name: "v4", Type: "varchar(512)", Nullable: false},
			{Name: "v5", Type: "varchar(512)", Nullable: false},
		},
		PrimaryKey: []string{"id"},
		UniqueIndexes: []StorageIndex{
			{
				Name:    "uidx_" + strings.ReplaceAll(tableName, "-", "_"),
				Columns: []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"},
			},
		},
	}
}

// ValidateStorage verifies the published schema for tableName without executing
// DDL. An empty table name selects the adapter's default table.
func ValidateStorage(ctx context.Context, db *gorm.DB, tableName string) error {
	descriptor := StorageSchema(tableName)
	if db == nil {
		return storageSchemaError("table", "database handle is required")
	}
	if descriptor.Table == "" || !validStorageIdentifier(descriptor.Table) {
		return storageSchemaError("table", "descriptor table name is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	migrator := db.WithContext(ctx).Migrator()
	if !migrator.HasTable(descriptor.Table) {
		return storageSchemaError("table", "required table %q is missing", descriptor.Table)
	}

	columns, err := migrator.ColumnTypes(descriptor.Table)
	if err != nil {
		return storageSchemaError("columns", "inspection failed")
	}
	columnsByName := make(map[string]gorm.ColumnType, len(columns))
	for _, column := range columns {
		columnsByName[column.Name()] = column
	}
	if len(columnsByName) != len(descriptor.Columns) {
		return storageSchemaError("columns", "required column set does not match")
	}

	dialect := db.Dialector.Name()
	primaryKey := make([]string, 0, len(descriptor.PrimaryKey))
	for _, required := range descriptor.Columns {
		actual, ok := columnsByName[required.Name]
		if !ok {
			return storageSchemaError("columns", "required column %q is missing", required.Name)
		}
		if !storageTypeMatches(dialect, required.Type, actual) {
			return storageSchemaError("types", "column %q has an incompatible type", required.Name)
		}
		nullable, known := actual.Nullable()
		if !known || nullable != required.Nullable {
			return storageSchemaError("nullability", "column %q nullability does not match", required.Name)
		}
		isPrimaryKey, known := actual.PrimaryKey()
		if !known {
			return storageSchemaError("primary key", "column %q key metadata is unavailable", required.Name)
		}
		if isPrimaryKey {
			primaryKey = append(primaryKey, required.Name)
		}
	}
	if !slices.Equal(primaryKey, descriptor.PrimaryKey) {
		return storageSchemaError("primary key", "required key columns do not match")
	}

	indexes, err := migrator.GetIndexes(descriptor.Table)
	if err != nil {
		return storageSchemaError("unique index", "inspection failed")
	}
	indexesByName := make(map[string]gorm.Index, len(indexes))
	for _, index := range indexes {
		indexesByName[index.Name()] = index
	}
	for _, required := range descriptor.UniqueIndexes {
		actual, ok := indexesByName[required.Name]
		if !ok {
			return storageSchemaError("unique index", "required index %q is missing", required.Name)
		}
		unique, known := actual.Unique()
		if !known || !unique || !slices.Equal(actual.Columns(), required.Columns) {
			return storageSchemaError("unique index", "index %q does not match", required.Name)
		}
	}

	return nil
}

func storageTypeMatches(dialect, required string, actual gorm.ColumnType) bool {
	databaseType := normalizeStorageType(actual.DatabaseTypeName())
	columnType, _ := actual.ColumnType()
	fullType := normalizeStorageType(columnType)

	switch required {
	case "bigint":
		if databaseType == "bigint" || databaseType == "bigserial" || databaseType == "int8" {
			return true
		}
		return dialect == "sqlite" && databaseType == "integer"
	case "varchar(512)":
		if dialect == "sqlite" && databaseType == "text" {
			return true
		}
		if databaseType != "varchar" && databaseType != "character varying" && databaseType != "varchar(512)" {
			return false
		}
		if length, known := actual.Length(); known {
			return length == 512
		}
		return fullType == "varchar(512)" || fullType == "character varying(512)" || databaseType == "varchar(512)"
	default:
		return databaseType == normalizeStorageType(required) || fullType == normalizeStorageType(required)
	}
}

func normalizeStorageType(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

func validStorageIdentifier(value string) bool {
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return value != ""
}

func storageSchemaError(category, format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return fmt.Errorf("authz storage schema v%d %s: %s", StorageSchemaVersion, category, detail)
}
