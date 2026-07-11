package authz

import (
	"context"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
	"gorm.io/gorm"
)

// StorageSchemaVersion identifies the published persistent policy schema.
const StorageSchemaVersion = 1

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

// StorageDialect identifies a physical database schema supported by strict validation.
type StorageDialect string

const (
	// StorageDialectPostgres is the production strict-storage dialect.
	StorageDialectPostgres StorageDialect = "postgres"
	// StorageDialectSQLite is supported for embedded consumers and hermetic tests.
	StorageDialectSQLite StorageDialect = "sqlite"
)

// StorageDescriptor is the complete public policy storage contract.
type StorageDescriptor struct {
	Version       int
	Dialect       StorageDialect
	Table         string
	Columns       []StorageColumn
	PrimaryKey    []string
	UniqueIndexes []StorageIndex
}

// StorageSchema returns the PostgreSQL schema descriptor for tableName. It is
// retained as the default production contract; new code may select a supported
// strict dialect with StorageSchemaForDialect.
func StorageSchema(tableName string) StorageDescriptor {
	return storageDescriptorFromInternal(internal.StorageSchema(tableName))
}

// StorageSchemaForDialect returns the exact physical schema for a strict
// validation dialect. PostgreSQL and SQLite are supported; MySQL remains
// available only through legacy auto migration.
func StorageSchemaForDialect(dialect StorageDialect, tableName string) (StorageDescriptor, error) {
	descriptor, err := internal.StorageSchemaForDialect(internal.StorageDialect(dialect), tableName)
	if err != nil {
		return StorageDescriptor{}, err
	}
	return storageDescriptorFromInternal(descriptor), nil
}

// ValidateStorage verifies the published PostgreSQL or SQLite schema for
// tableName without executing DDL. Other dialects return a sanitized error.
func ValidateStorage(ctx context.Context, db *gorm.DB, tableName string) error {
	return internal.ValidateStorage(ctx, db, tableName)
}

func storageDescriptorFromInternal(descriptor internal.StorageDescriptor) StorageDescriptor {
	columns := make([]StorageColumn, len(descriptor.Columns))
	for i, column := range descriptor.Columns {
		columns[i] = StorageColumn(column)
	}
	indexes := make([]StorageIndex, len(descriptor.UniqueIndexes))
	for i, index := range descriptor.UniqueIndexes {
		indexes[i] = StorageIndex{
			Name:    index.Name,
			Columns: append([]string(nil), index.Columns...),
		}
	}
	return StorageDescriptor{
		Version:       descriptor.Version,
		Dialect:       StorageDialect(descriptor.Dialect),
		Table:         descriptor.Table,
		Columns:       columns,
		PrimaryKey:    append([]string(nil), descriptor.PrimaryKey...),
		UniqueIndexes: indexes,
	}
}
