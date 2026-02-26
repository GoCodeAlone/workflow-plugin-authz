package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// CasbinModule implements sdk.ModuleInstance and holds a Casbin enforcer
// loaded from inline config (model text + policy rows + role assignments),
// a file adapter, or a GORM adapter backed by postgres/mysql/sqlite3.
type CasbinModule struct {
	name     string
	config   casbinConfig
	mu       sync.RWMutex
	enforcer *casbin.Enforcer

	// polling watcher fields
	stopCh chan struct{}
	doneCh chan struct{}
}

// adapterConfig describes the storage backend for policies.
type adapterConfig struct {
	// Type is "memory" (default), "file", or "gorm".
	Type string `yaml:"type"`

	// File adapter fields.
	Path string `yaml:"path"`

	// GORM adapter fields.
	Driver    string `yaml:"driver"` // "postgres", "mysql", or "sqlite3"
	DSN       string `yaml:"dsn"`
	TableName string `yaml:"table_name"` // optional; defaults to "casbin_rule"
}

// watcherConfig describes the optional polling reload behaviour.
type watcherConfig struct {
	// Type is "none" (default) or "polling".
	Type string `yaml:"type"`
	// Interval is the reload interval for polling watcher (default 30s).
	Interval time.Duration `yaml:"interval"`
}

// casbinConfig holds the parsed configuration for an authz.casbin module.
type casbinConfig struct {
	// Model is a PERM model definition (ini-style text).
	Model string `yaml:"model"`
	// Policies is a list of [sub, obj, act] policy rows (memory adapter only).
	Policies [][]string `yaml:"policies"`
	// RoleAssignments is a list of [user, role] grouping rows (memory adapter only).
	RoleAssignments [][]string `yaml:"roleAssignments"`
	// Adapter describes the storage backend.
	Adapter adapterConfig `yaml:"adapter"`
	// Watcher describes the optional polling watcher.
	Watcher watcherConfig `yaml:"watcher"`
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

	// Parse adapter section.
	if adapterRaw, ok := raw["adapter"].(map[string]any); ok {
		cfg.Adapter = parseAdapterConfig(adapterRaw)
	}

	// Parse watcher section.
	if watcherRaw, ok := raw["watcher"].(map[string]any); ok {
		cfg.Watcher = parseWatcherConfig(watcherRaw)
	}

	return cfg, nil
}

// parseAdapterConfig parses the adapter sub-map.
func parseAdapterConfig(raw map[string]any) adapterConfig {
	var a adapterConfig
	a.Type, _ = raw["type"].(string)
	a.Path, _ = raw["path"].(string)
	a.Driver, _ = raw["driver"].(string)
	a.DSN, _ = raw["dsn"].(string)
	a.TableName, _ = raw["table_name"].(string)
	return a
}

// parseWatcherConfig parses the watcher sub-map.
func parseWatcherConfig(raw map[string]any) watcherConfig {
	var w watcherConfig
	w.Type, _ = raw["type"].(string)
	if iv, ok := raw["interval"].(string); ok && iv != "" {
		if d, err := time.ParseDuration(iv); err == nil {
			w.Interval = d
		}
	}
	return w
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

// buildAdapter returns a persist.Adapter for the configured backend.
func (m *CasbinModule) buildAdapter() (persist.Adapter, error) {
	switch strings.ToLower(m.config.Adapter.Type) {
	case "", "memory":
		return newInMemoryAdapter(m.config.Policies, m.config.RoleAssignments), nil

	case "file":
		if m.config.Adapter.Path == "" {
			return nil, fmt.Errorf("authz.casbin %q: adapter.path is required for file adapter", m.name)
		}
		return fileadapter.NewAdapter(m.config.Adapter.Path), nil

	case "gorm":
		return m.buildGORMAdapter()

	default:
		return nil, fmt.Errorf("authz.casbin %q: unknown adapter type %q", m.name, m.config.Adapter.Type)
	}
}

// buildGORMAdapter opens a GORM connection and returns a gorm-adapter.
func (m *CasbinModule) buildGORMAdapter() (persist.Adapter, error) {
	if m.config.Adapter.DSN == "" {
		return nil, fmt.Errorf("authz.casbin %q: adapter.dsn is required for gorm adapter", m.name)
	}

	silentLogger := gormlogger.Default.LogMode(gormlogger.Silent)
	gormCfg := &gorm.Config{Logger: silentLogger}

	var db *gorm.DB
	var err error

	switch strings.ToLower(m.config.Adapter.Driver) {
	case "postgres", "postgresql":
		db, err = gorm.Open(postgres.Open(m.config.Adapter.DSN), gormCfg)
	case "mysql":
		db, err = gorm.Open(mysql.Open(m.config.Adapter.DSN), gormCfg)
	case "sqlite3", "sqlite":
		db, err = gorm.Open(openSQLite(m.config.Adapter.DSN), gormCfg)
	default:
		return nil, fmt.Errorf("authz.casbin %q: unsupported gorm driver %q (supported: postgres, mysql, sqlite3)", m.name, m.config.Adapter.Driver)
	}
	if err != nil {
		return nil, fmt.Errorf("authz.casbin %q: open gorm db: %w", m.name, err)
	}

	a, err := newGORMAdapter(db, m.config.Adapter.TableName)
	if err != nil {
		return nil, fmt.Errorf("authz.casbin %q: create gorm adapter: %w", m.name, err)
	}
	return a, nil
}

// Init builds the Casbin enforcer from the configured adapter.
func (m *CasbinModule) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	md, err := model.NewModelFromString(m.config.Model)
	if err != nil {
		return fmt.Errorf("authz.casbin %q: parse model: %w", m.name, err)
	}

	adapter, err := m.buildAdapter()
	if err != nil {
		return fmt.Errorf("authz.casbin %q: build adapter: %w", m.name, err)
	}

	e, err := casbin.NewEnforcer(md, adapter)
	if err != nil {
		return fmt.Errorf("authz.casbin %q: create enforcer: %w", m.name, err)
	}

	m.enforcer = e
	return nil
}

// Start begins the polling watcher goroutine if watcher.type is "polling".
func (m *CasbinModule) Start(_ context.Context) error {
	if strings.ToLower(m.config.Watcher.Type) != "polling" {
		return nil
	}

	interval := m.config.Watcher.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	m.mu.Lock()
	m.stopCh = make(chan struct{})
	m.doneCh = make(chan struct{})
	m.mu.Unlock()

	go m.pollLoop(interval)
	return nil
}

// pollLoop reloads policies from the adapter on each tick.
func (m *CasbinModule) pollLoop(interval time.Duration) {
	defer close(m.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.enforcer != nil {
				_ = m.enforcer.LoadPolicy()
			}
			m.mu.Unlock()
		}
	}
}

// Stop shuts down the polling watcher if running.
func (m *CasbinModule) Stop(_ context.Context) error {
	m.mu.RLock()
	stopCh := m.stopCh
	doneCh := m.doneCh
	m.mu.RUnlock()

	if stopCh != nil {
		close(stopCh)
		<-doneCh
		m.mu.Lock()
		m.stopCh = nil
		m.doneCh = nil
		m.mu.Unlock()
	}
	return nil
}

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

// AddPolicy adds a policy rule and saves it to the adapter.
func (m *CasbinModule) AddPolicy(rule []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enforcer == nil {
		return false, fmt.Errorf("authz.casbin %q: enforcer not initialized", m.name)
	}
	ok, err := m.enforcer.AddPolicy(toInterfaceSlice(rule)...)
	if err != nil {
		return false, err
	}
	if ok {
		if err := m.enforcer.SavePolicy(); err != nil {
			return false, err
		}
	}
	return ok, nil
}

// RemovePolicy removes a policy rule and saves the adapter.
func (m *CasbinModule) RemovePolicy(rule []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enforcer == nil {
		return false, fmt.Errorf("authz.casbin %q: enforcer not initialized", m.name)
	}
	ok, err := m.enforcer.RemovePolicy(toInterfaceSlice(rule)...)
	if err != nil {
		return false, err
	}
	if ok {
		if err := m.enforcer.SavePolicy(); err != nil {
			return false, err
		}
	}
	return ok, nil
}

// AddGroupingPolicy adds a role mapping and saves the adapter.
func (m *CasbinModule) AddGroupingPolicy(rule []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enforcer == nil {
		return false, fmt.Errorf("authz.casbin %q: enforcer not initialized", m.name)
	}
	ok, err := m.enforcer.AddGroupingPolicy(toInterfaceSlice(rule)...)
	if err != nil {
		return false, err
	}
	if ok {
		if err := m.enforcer.SavePolicy(); err != nil {
			return false, err
		}
	}
	return ok, nil
}

// RemoveGroupingPolicy removes a role mapping and saves the adapter.
func (m *CasbinModule) RemoveGroupingPolicy(rule []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enforcer == nil {
		return false, fmt.Errorf("authz.casbin %q: enforcer not initialized", m.name)
	}
	ok, err := m.enforcer.RemoveGroupingPolicy(toInterfaceSlice(rule)...)
	if err != nil {
		return false, err
	}
	if ok {
		if err := m.enforcer.SavePolicy(); err != nil {
			return false, err
		}
	}
	return ok, nil
}

// toInterfaceSlice converts []string to []interface{} for casbin variadic calls.
func toInterfaceSlice(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// Name returns the module name.
func (m *CasbinModule) Name() string { return m.name }

// --- in-memory Casbin adapter ---

// inMemoryAdapter implements persist.Adapter with an in-memory policy store
// that is fully mutable: AddPolicy / RemovePolicy / SavePolicy all work.
type inMemoryAdapter struct {
	mu              sync.RWMutex
	policies        [][]string
	roleAssignments [][]string
}

func newInMemoryAdapter(policies, roleAssignments [][]string) *inMemoryAdapter {
	p := make([][]string, len(policies))
	copy(p, policies)
	r := make([][]string, len(roleAssignments))
	copy(r, roleAssignments)
	return &inMemoryAdapter{
		policies:        p,
		roleAssignments: r,
	}
}

// LoadPolicy loads all policy rules into the model.
func (a *inMemoryAdapter) LoadPolicy(m model.Model) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
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

// SavePolicy persists the current model state back to the in-memory store.
// This replaces a.policies and a.roleAssignments with whatever the model holds.
func (a *inMemoryAdapter) SavePolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.policies = nil
	if pMap, ok := m["p"]; ok {
		if policy, ok := pMap["p"]; ok {
			for _, tokens := range policy.Policy {
				row := make([]string, len(tokens))
				copy(row, tokens)
				a.policies = append(a.policies, row)
			}
		}
	}

	a.roleAssignments = nil
	if gMap, ok := m["g"]; ok {
		if grp, ok := gMap["g"]; ok {
			for _, tokens := range grp.Policy {
				row := make([]string, len(tokens))
				copy(row, tokens)
				a.roleAssignments = append(a.roleAssignments, row)
			}
		}
	}

	return nil
}

// AddPolicy appends a policy row to the in-memory store.
// sec is "p" for normal policies, "g" for role assignments.
// SavePolicy is always called after AddPolicy by CasbinModule methods, which
// overwrites both slices from the model, so we append to the correct bucket
// here to keep the intermediate state consistent.
func (a *inMemoryAdapter) AddPolicy(sec string, _ string, rule []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row := make([]string, len(rule))
	copy(row, rule)
	if sec == "g" {
		a.roleAssignments = append(a.roleAssignments, row)
	} else {
		a.policies = append(a.policies, row)
	}
	return nil
}

// RemovePolicy removes a policy row from the in-memory store.
func (a *inMemoryAdapter) RemovePolicy(sec string, _ string, rule []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sec == "g" {
		a.roleAssignments = removeRow(a.roleAssignments, rule)
	} else {
		a.policies = removeRow(a.policies, rule)
	}
	return nil
}

// RemoveFilteredPolicy removes rows matching the prefix filter.
func (a *inMemoryAdapter) RemoveFilteredPolicy(sec string, _ string, fieldIndex int, fieldValues ...string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sec == "g" {
		var kept [][]string
		for _, row := range a.roleAssignments {
			if !matchesFilter(row, fieldIndex, fieldValues) {
				kept = append(kept, row)
			}
		}
		a.roleAssignments = kept
	} else {
		var kept [][]string
		for _, row := range a.policies {
			if !matchesFilter(row, fieldIndex, fieldValues) {
				kept = append(kept, row)
			}
		}
		a.policies = kept
	}
	return nil
}

// removeRow removes the first row that equals target (element-wise).
func removeRow(rows [][]string, target []string) [][]string {
	for i, row := range rows {
		if sliceEqual(row, target) {
			return append(rows[:i:i], rows[i+1:]...)
		}
	}
	return rows
}

// matchesFilter returns true when row[fieldIndex:fieldIndex+len(values)] == values.
func matchesFilter(row []string, fieldIndex int, values []string) bool {
	for i, v := range values {
		idx := fieldIndex + i
		if idx >= len(row) {
			return false
		}
		if v != "" && row[idx] != v {
			return false
		}
	}
	return true
}

// sliceEqual reports whether a and b have identical elements.
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
