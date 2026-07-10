package authz

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
)

// MigrationMode controls whether the runtime owns schema migration or only
// validates a schema owned by the host application.
type MigrationMode string

const (
	// MigrationModeAuto creates or updates the policy schema before loading it.
	MigrationModeAuto MigrationMode = "auto"
	// MigrationModeValidate verifies PostgreSQL or SQLite without executing DDL.
	// MySQL remains compatible with MigrationModeAuto only.
	MigrationModeValidate MigrationMode = "validate"
)

// StorageConfig describes persistent policy storage for a standalone runtime.
type StorageConfig struct {
	Driver        string
	DSN           string
	TableName     string
	MigrationMode MigrationMode
}

// RuntimeConfig configures a standalone authorization runtime.
//
// Persistent storage requires an explicit migration mode. Compatibility
// decoders for legacy module configuration apply MigrationModeAuto before
// constructing this typed configuration.
type RuntimeConfig struct {
	Storage *StorageConfig
}

// Validate checks the strict portions of the standalone runtime contract.
func (c RuntimeConfig) Validate() error {
	if c.Storage == nil {
		return nil
	}
	if err := internal.ValidateMigrationMode(internal.MigrationMode(c.Storage.MigrationMode)); err != nil {
		return fmt.Errorf("authz runtime: %w", err)
	}
	return nil
}

// DecodeMigrationMode decodes migration_mode from a raw YAML/module config.
// Only an absent field receives the legacy-compatible auto default.
func DecodeMigrationMode(raw map[string]any) (MigrationMode, error) {
	mode, err := internal.DecodeMigrationMode(raw)
	return MigrationMode(mode), err
}
