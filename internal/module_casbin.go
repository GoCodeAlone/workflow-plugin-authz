package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// CasbinModule implements sdk.ModuleInstance and holds a Casbin enforcer
// loaded from inline config (model text + policy rows + role assignments).
type CasbinModule struct {
	name     string
	config   casbinConfig
	mu       sync.RWMutex
	enforcer *casbin.Enforcer
}

// casbinConfig holds the parsed configuration for an authz.casbin module.
type casbinConfig struct {
	// Model is a PERM model definition (ini-style text).
	Model string `yaml:"model"`
	// Policies is a list of [sub, obj, act] policy rows.
	Policies [][]string `yaml:"policies"`
	// RoleAssignments is a list of [user, role] grouping rows.
	RoleAssignments [][]string `yaml:"roleAssignments"`
}

// newCasbinModule parses the config map and returns a CasbinModule.
func newCasbinModule(name string, config map[string]any) (*CasbinModule, error) {
	cfg, err := parseCasbinConfig(config)
	if err != nil {
		return nil, fmt.Errorf("authz.casbin %q: %w", name, err)
	}
	return &CasbinModule{
		name:   name,
		config: cfg,
	}, nil
}

// parseCasbinConfig converts a raw config map to casbinConfig.
func parseCasbinConfig(raw map[string]any) (casbinConfig, error) {
	var cfg casbinConfig

	modelText, _ := raw["model"].(string)
	cfg.Model = strings.TrimSpace(modelText)
	if cfg.Model == "" {
		return cfg, fmt.Errorf("config.model is required")
	}

	if policies, ok := raw["policies"].([]any); ok {
		for i, p := range policies {
			row, err := toStringSlice(p)
			if err != nil {
				return cfg, fmt.Errorf("config.policies[%d]: %w", i, err)
			}
			if len(row) < 3 {
				return cfg, fmt.Errorf("config.policies[%d]: expected [sub, obj, act], got %v", i, row)
			}
			cfg.Policies = append(cfg.Policies, row)
		}
	}

	if assignments, ok := raw["roleAssignments"].([]any); ok {
		for i, a := range assignments {
			row, err := toStringSlice(a)
			if err != nil {
				return cfg, fmt.Errorf("config.roleAssignments[%d]: %w", i, err)
			}
			if len(row) < 2 {
				return cfg, fmt.Errorf("config.roleAssignments[%d]: expected [user, role], got %v", i, row)
			}
			cfg.RoleAssignments = append(cfg.RoleAssignments, row)
		}
	}

	return cfg, nil
}

// toStringSlice converts an []any (from YAML/JSON) to []string.
func toStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case []any:
		s := make([]string, len(t))
		for i, item := range t {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("element %d is not a string: %v (%T)", i, item, item)
			}
			s[i] = str
		}
		return s, nil
	case []string:
		return t, nil
	default:
		return nil, fmt.Errorf("expected []any or []string, got %T", v)
	}
}

// Init builds the Casbin enforcer from inline model and policies.
func (m *CasbinModule) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	md, err := model.NewModelFromString(m.config.Model)
	if err != nil {
		return fmt.Errorf("authz.casbin %q: parse model: %w", m.name, err)
	}

	adapter := newInMemoryAdapter(m.config.Policies, m.config.RoleAssignments)
	e, err := casbin.NewEnforcer(md, adapter)
	if err != nil {
		return fmt.Errorf("authz.casbin %q: create enforcer: %w", m.name, err)
	}

	m.enforcer = e
	return nil
}

// Start is a no-op; the enforcer is ready after Init.
func (m *CasbinModule) Start(_ context.Context) error { return nil }

// Stop is a no-op.
func (m *CasbinModule) Stop(_ context.Context) error { return nil }

// Enforce checks whether sub can perform act on obj.
// It is safe for concurrent use.
func (m *CasbinModule) Enforce(sub, obj, act string) (bool, error) {
	m.mu.RLock()
	e := m.enforcer
	m.mu.RUnlock()
	if e == nil {
		return false, fmt.Errorf("authz.casbin %q: enforcer not initialized", m.name)
	}
	return e.Enforce(sub, obj, act)
}

// Name returns the module name.
func (m *CasbinModule) Name() string { return m.name }

// --- in-memory Casbin adapter ---

// inMemoryAdapter implements persist.Adapter with an in-memory policy store.
type inMemoryAdapter struct {
	policies        [][]string
	roleAssignments [][]string
}

func newInMemoryAdapter(policies, roleAssignments [][]string) persist.Adapter {
	return &inMemoryAdapter{
		policies:        policies,
		roleAssignments: roleAssignments,
	}
}

// LoadPolicy loads all policy rules into the model.
func (a *inMemoryAdapter) LoadPolicy(m model.Model) error {
	for _, p := range a.policies {
		line := "p, " + strings.Join(p, ", ")
		if err := persist.LoadPolicyLine(line, m); err != nil {
			return err
		}
	}
	for _, g := range a.roleAssignments {
		line := "g, " + strings.Join(g, ", ")
		if err := persist.LoadPolicyLine(line, m); err != nil {
			return err
		}
	}
	return nil
}

// SavePolicy is not supported for the in-memory adapter (read-only config).
func (a *inMemoryAdapter) SavePolicy(_ model.Model) error {
	return fmt.Errorf("inMemoryAdapter: SavePolicy is not supported")
}

// AddPolicy is not supported.
func (a *inMemoryAdapter) AddPolicy(_ string, _ string, _ []string) error {
	return fmt.Errorf("inMemoryAdapter: AddPolicy is not supported")
}

// RemovePolicy is not supported.
func (a *inMemoryAdapter) RemovePolicy(_ string, _ string, _ []string) error {
	return fmt.Errorf("inMemoryAdapter: RemovePolicy is not supported")
}

// RemoveFilteredPolicy is not supported.
func (a *inMemoryAdapter) RemoveFilteredPolicy(_ string, _ string, _ int, _ ...string) error {
	return fmt.Errorf("inMemoryAdapter: RemoveFilteredPolicy is not supported")
}
