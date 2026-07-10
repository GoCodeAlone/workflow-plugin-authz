package authz

import (
	"context"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
	"gorm.io/gorm"
)

// StorageSchemaVersion identifies the published persistent policy schema.
const StorageSchemaVersion = internal.StorageSchemaVersion

// StorageColumn describes one required policy storage column.
type StorageColumn = internal.StorageColumn

// StorageIndex describes one required policy storage index.
type StorageIndex = internal.StorageIndex

// StorageDescriptor is the complete public policy storage contract.
type StorageDescriptor = internal.StorageDescriptor

// StorageSchema returns the published schema descriptor for tableName. An empty
// table name selects the adapter's default table.
func StorageSchema(tableName string) StorageDescriptor {
	return internal.StorageSchema(tableName)
}

// ValidateStorage verifies the published schema for tableName without executing
// DDL. An empty table name selects the adapter's default table.
func ValidateStorage(ctx context.Context, db *gorm.DB, tableName string) error {
	return internal.ValidateStorage(ctx, db, tableName)
}
