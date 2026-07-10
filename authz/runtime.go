package authz

import "fmt"

// MigrationMode controls whether the runtime owns schema migration or only
// validates a schema owned by the host application.
type MigrationMode string

const (
	// MigrationModeAuto creates or updates the policy schema before loading it.
	MigrationModeAuto MigrationMode = "auto"
	// MigrationModeValidate verifies the policy schema without executing DDL.
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
	if err := validateMigrationMode(c.Storage.MigrationMode); err != nil {
		return fmt.Errorf("authz runtime: %w", err)
	}
	return nil
}

// DecodeMigrationMode decodes migration_mode from a raw YAML/module config.
// Only an absent field receives the legacy-compatible auto default.
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
	if err := validateMigrationMode(decoded); err != nil {
		return "", err
	}
	return decoded, nil
}

func validateMigrationMode(mode MigrationMode) error {
	switch mode {
	case MigrationModeAuto, MigrationModeValidate:
		return nil
	case "":
		return fmt.Errorf("migration mode (migration_mode) is required")
	default:
		return fmt.Errorf("migration mode (migration_mode) %q is unsupported", mode)
	}
}
