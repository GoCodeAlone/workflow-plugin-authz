package authz

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
	"github.com/casbin/casbin/v2/model"
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

// SeedConfig describes an immutable in-memory policy source.
type SeedConfig struct {
	Policies        [][]string
	RoleAssignments [][]string
}

// RuntimeConfig configures exactly one immutable policy source.
type RuntimeConfig struct {
	Model   string
	Storage *StorageConfig
	Seed    *SeedConfig
}

// DecisionRequest is one RBAC decision tuple.
type DecisionRequest struct {
	Subject string
	Object  string
	Action  string
}

// Decision is the immutable result of evaluating a request.
type Decision struct {
	Allowed bool
}

// PolicyRule is one three-field policy row.
type PolicyRule struct {
	Subject string
	Object  string
	Action  string
}

// HealthStatus classifies the runtime's current storage reachability.
type HealthStatus string

const (
	// HealthUnknown means storage health could not be determined, including a
	// canceled caller context or a closed runtime.
	HealthUnknown HealthStatus = "unknown"
	// HealthReady means the immutable runtime is usable and storage, when
	// configured, responded to the bounded ping.
	HealthReady HealthStatus = "ready"
	// HealthDegraded means persistent storage failed its ping. Loaded decisions
	// remain available from the immutable snapshot.
	HealthDegraded HealthStatus = "degraded"
)

// Health is a sanitized on-demand storage health result.
type Health struct {
	Status HealthStatus
}

// ErrRuntimeClosed reports an operation attempted after Close.
var ErrRuntimeClosed = errors.New("authz runtime closed")

const healthPingLimit = time.Second

// Runtime owns one immutable Casbin snapshot without global registration,
// watcher startup, or mutation methods.
type Runtime struct {
	mu         sync.RWMutex
	module     *internal.CasbinModule
	policies   []PolicyRule
	persistent bool
	ping       func(context.Context) error
	closed     bool
	closeErr   error
}

// Validate preserves the storage-mode validation contract published before
// standalone construction was added. NewRuntime enforces the full config.
func (c RuntimeConfig) Validate() error {
	if c.Storage == nil {
		return nil
	}
	if err := internal.ValidateMigrationMode(internal.MigrationMode(c.Storage.MigrationMode)); err != nil {
		return fmt.Errorf("authz runtime: %w", err)
	}
	return nil
}

// NewRuntime constructs a standalone immutable authorization runtime without
// Modular, global registration, mutation methods, or policy watchers.
func NewRuntime(ctx context.Context, config RuntimeConfig) (*Runtime, error) {
	if err := validateRuntimeConfig(config); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("authz runtime: %w", err)
	}
	raw := map[string]any{"model": config.Model}
	persistent := config.Storage != nil
	if persistent {
		raw["adapter"] = map[string]any{
			"type":           "gorm",
			"driver":         config.Storage.Driver,
			"dsn":            config.Storage.DSN,
			"table_name":     config.Storage.TableName,
			"migration_mode": string(config.Storage.MigrationMode),
		}
	} else {
		raw["policies"] = rowsToAny(config.Seed.Policies)
		raw["roleAssignments"] = rowsToAny(config.Seed.RoleAssignments)
	}

	module, err := internal.NewCasbinModuleFromConfig("standalone", raw)
	if err == nil {
		err = module.InitContext(ctx)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("authz runtime: %w", ctxErr)
		}
		if persistent {
			if internal.IsStorageValidationError(err) {
				return nil, err
			}
			return nil, fmt.Errorf("authz runtime: persistent storage unavailable")
		}
		return nil, fmt.Errorf("authz runtime: initialize seed: %w", err)
	}
	rows, err := module.PolicySnapshot()
	if err != nil {
		_ = module.CloseStorage()
		return nil, fmt.Errorf("authz runtime: load immutable snapshot: %w", err)
	}
	policies := make([]PolicyRule, 0, len(rows))
	for i, row := range rows {
		if len(row) != 3 {
			_ = module.CloseStorage()
			return nil, fmt.Errorf("authz runtime: policy %d requires exactly subject, object, and action", i)
		}
		policies = append(policies, PolicyRule{Subject: row[0], Object: row[1], Action: row[2]})
	}
	slices.SortFunc(policies, func(a, b PolicyRule) int {
		return cmp.Or(cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Object, b.Object), cmp.Compare(a.Action, b.Action))
	})
	runtime := &Runtime{module: module, policies: policies, persistent: persistent}
	if persistent {
		runtime.ping = func(ctx context.Context) error {
			_, err := module.PingStorage(ctx)
			return err
		}
	}
	return runtime, nil
}

func validateRuntimeConfig(config RuntimeConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(config.Model) == "" {
		return fmt.Errorf("authz runtime: model is required")
	}
	if _, err := model.NewModelFromString(config.Model); err != nil {
		return fmt.Errorf("authz runtime: invalid model")
	}
	if (config.Storage == nil) == (config.Seed == nil) {
		return fmt.Errorf("authz runtime: exactly one policy source is required")
	}
	if config.Storage != nil {
		if strings.TrimSpace(config.Storage.Driver) == "" || strings.TrimSpace(config.Storage.DSN) == "" {
			return fmt.Errorf("authz runtime: storage driver and DSN are required")
		}
		return nil
	}
	for i, row := range config.Seed.Policies {
		if len(row) != 3 {
			return fmt.Errorf("authz runtime: policy %d requires exactly subject, object, and action", i)
		}
	}
	for i, row := range config.Seed.RoleAssignments {
		if len(row) != 2 {
			return fmt.Errorf("authz runtime: role assignment %d requires exactly subject and role", i)
		}
	}
	return nil
}

// Decide evaluates one request against the loaded immutable snapshot.
func (r *Runtime) Decide(ctx context.Context, request DecisionRequest) (Decision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Decision{}, ErrRuntimeClosed
	}
	allowed, err := r.module.Enforce(request.Subject, request.Object, request.Action)
	if err != nil {
		return Decision{}, fmt.Errorf("authz runtime: decide: %w", err)
	}
	return Decision{Allowed: allowed}, nil
}

// Policies returns a copy of the deterministic startup policy snapshot.
func (r *Runtime) Policies(ctx context.Context) ([]PolicyRule, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrRuntimeClosed
	}
	return slices.Clone(r.policies), nil
}

// Health performs a bounded storage ping using the caller's context. It never
// reloads policy and never gates decisions from a successfully loaded snapshot.
func (r *Runtime) Health(ctx context.Context) Health {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Health{Status: HealthUnknown}
	}
	if !r.persistent {
		return Health{Status: HealthReady}
	}
	if err := ctx.Err(); err != nil {
		return Health{Status: HealthUnknown}
	}
	pingCtx, cancel := context.WithTimeout(ctx, healthPingLimit)
	defer cancel()
	if err := r.ping(pingCtx); err != nil {
		if ctx.Err() != nil {
			return Health{Status: HealthUnknown}
		}
		return Health{Status: HealthDegraded}
	}
	return Health{Status: HealthReady}
}

// Close releases persistent storage and invalidates future operations. It is
// idempotent and safe to call concurrently with decisions.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	r.closeErr = r.module.CloseStorage()
	return r.closeErr
}

func rowsToAny(rows [][]string) []any {
	out := make([]any, len(rows))
	for i, row := range rows {
		values := make([]any, len(row))
		for j, value := range row {
			values[j] = value
		}
		out[i] = values
	}
	return out
}

// DecodeMigrationMode decodes migration_mode from raw module configuration.
func DecodeMigrationMode(raw map[string]any) (MigrationMode, error) {
	mode, err := internal.DecodeMigrationMode(raw)
	return MigrationMode(mode), err
}
