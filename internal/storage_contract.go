package internal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"
)

const (
	StorageSchemaVersion = 1

	defaultStorageTable = "casbin_rule"
)

type MigrationMode string

const (
	MigrationModeAuto     MigrationMode = "auto"
	MigrationModeValidate MigrationMode = "validate"
)

type StorageColumn struct {
	Name     string
	Type     string
	Nullable bool
}

type StorageIndex struct {
	Name    string
	Columns []string
}

type StorageDialect string

const (
	StorageDialectPostgres StorageDialect = "postgres"
	StorageDialectSQLite   StorageDialect = "sqlite"
)

type StorageDescriptor struct {
	Version       int
	Dialect       StorageDialect
	Table         string
	Columns       []StorageColumn
	PrimaryKey    []string
	UniqueIndexes []StorageIndex
}

func DecodeMigrationMode(raw map[string]any) (MigrationMode, error) {
	value, present := raw["migration_mode"]
	if !present {
		return MigrationModeAuto, nil
	}
	mode, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("migration_mode must be a string, got %T", value)
	}
	decoded := MigrationMode(mode)
	if err := ValidateMigrationMode(decoded); err != nil {
		return "", err
	}
	return decoded, nil
}

func ValidateMigrationMode(mode MigrationMode) error {
	switch mode {
	case MigrationModeAuto, MigrationModeValidate:
		return nil
	case "":
		return fmt.Errorf("migration mode (migration_mode) is required")
	default:
		return fmt.Errorf("migration mode (migration_mode) %q is unsupported", mode)
	}
}

func StorageSchema(tableName string) StorageDescriptor {
	descriptor, _ := StorageSchemaForDialect(StorageDialectPostgres, tableName)
	return descriptor
}

func StorageSchemaForDialect(dialect StorageDialect, tableName string) (StorageDescriptor, error) {
	if tableName == "" {
		tableName = defaultStorageTable
	}
	descriptor := StorageDescriptor{
		Version:    StorageSchemaVersion,
		Dialect:    dialect,
		Table:      tableName,
		PrimaryKey: []string{"id"},
		UniqueIndexes: []StorageIndex{
			{
				Name:    "uidx_" + strings.ReplaceAll(tableName, "-", "_"),
				Columns: []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"},
			},
		},
	}
	switch dialect {
	case StorageDialectPostgres:
		descriptor.Columns = storageColumns("bigint", "varchar(512)")
	case StorageDialectSQLite:
		descriptor.Columns = storageColumns("integer", "text")
	default:
		return StorageDescriptor{}, newStorageValidationError("dialect")
	}
	return descriptor, nil
}

func storageColumns(idType, valueType string) []StorageColumn {
	return []StorageColumn{
		{Name: "id", Type: idType, Nullable: false},
		{Name: "ptype", Type: valueType, Nullable: false},
		{Name: "v0", Type: valueType, Nullable: false},
		{Name: "v1", Type: valueType, Nullable: false},
		{Name: "v2", Type: valueType, Nullable: false},
		{Name: "v3", Type: valueType, Nullable: false},
		{Name: "v4", Type: valueType, Nullable: false},
		{Name: "v5", Type: valueType, Nullable: false},
	}
}

func ValidateStorage(ctx context.Context, db *gorm.DB, tableName string) error {
	if db == nil {
		return newStorageValidationError("table")
	}
	dialect := StorageDialect(db.Dialector.Name())
	descriptor, err := StorageSchemaForDialect(dialect, tableName)
	if err != nil {
		return err
	}
	if descriptor.Table == "" || !validStorageIdentifier(descriptor.Table) {
		return newStorageValidationError("table")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	migrator := db.WithContext(ctx).Migrator()
	if !migrator.HasTable(descriptor.Table) {
		return newStorageValidationError("table")
	}

	columns, err := migrator.ColumnTypes(descriptor.Table)
	if err != nil {
		return newStorageValidationError("columns")
	}
	columnsByName := make(map[string]gorm.ColumnType, len(columns))
	for _, column := range columns {
		columnsByName[column.Name()] = column
	}
	if len(columnsByName) != len(descriptor.Columns) {
		return newStorageValidationError("columns")
	}

	primaryKey := make([]string, 0, len(descriptor.PrimaryKey))
	for _, required := range descriptor.Columns {
		actual, ok := columnsByName[required.Name]
		if !ok {
			return newStorageValidationError("columns")
		}
		if !storageTypeMatches(required.Type, actual) {
			return newStorageValidationError("types")
		}
		nullable, known := actual.Nullable()
		if !known || nullable != required.Nullable {
			return newStorageValidationError("nullability")
		}
		isPrimaryKey, known := actual.PrimaryKey()
		if !known {
			return newStorageValidationError("primary key")
		}
		if isPrimaryKey {
			primaryKey = append(primaryKey, required.Name)
		}
	}
	if !slices.Equal(primaryKey, descriptor.PrimaryKey) {
		return newStorageValidationError("primary key")
	}

	indexes, err := migrator.GetIndexes(descriptor.Table)
	if err != nil {
		return newStorageValidationError("unique index")
	}
	uniqueIndexes := make(map[string]gorm.Index, len(indexes))
	for _, index := range indexes {
		primary, known := index.PrimaryKey()
		if !known {
			return newStorageValidationError("unique index")
		}
		if primary {
			continue
		}
		unique, known := index.Unique()
		if !known {
			return newStorageValidationError("unique index")
		}
		if unique {
			uniqueIndexes[index.Name()] = index
		}
	}
	if len(uniqueIndexes) != len(descriptor.UniqueIndexes) {
		return newStorageValidationError("unique index")
	}
	for _, required := range descriptor.UniqueIndexes {
		actual, ok := uniqueIndexes[required.Name]
		if !ok {
			return newStorageValidationError("unique index")
		}
		if !slices.Equal(actual.Columns(), required.Columns) {
			return newStorageValidationError("unique index")
		}
	}

	return nil
}

type storageValidationError struct {
	category string
}

func newStorageValidationError(category string) error {
	return &storageValidationError{category: category}
}

func (e *storageValidationError) Error() string {
	return fmt.Sprintf("authz storage schema v%d %s", StorageSchemaVersion, e.category)
}

func isStorageValidationError(err error) bool {
	_, ok := errors.AsType[*storageValidationError](err)
	return ok
}

func storageTypeMatches(required string, actual gorm.ColumnType) bool {
	databaseType := normalizeStorageType(actual.DatabaseTypeName())
	columnType, _ := actual.ColumnType()
	fullType := normalizeStorageType(columnType)

	switch required {
	case "bigint":
		return databaseType == "bigint" || databaseType == "bigserial" || databaseType == "int8"
	case "integer":
		return databaseType == "integer"
	case "varchar(512)":
		if databaseType != "varchar" && databaseType != "character varying" && databaseType != "varchar(512)" {
			return false
		}
		if length, known := actual.Length(); known {
			return length == 512
		}
		return fullType == "varchar(512)" || fullType == "character varying(512)" || databaseType == "varchar(512)"
	case "text":
		return databaseType == "text"
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
