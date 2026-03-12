package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- file adapter tests ---

func TestFileAdapter_LoadPolicy(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "policy.csv")

	// Write a minimal CSV file (casbin file adapter format).
	content := "p, admin, /api/*, *\ng, alice, admin\n"
	if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
		t.Fatalf("write CSV: %v", err)
	}

	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type": "file",
			"path": csvPath,
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// alice inherits admin → allowed
	allowed, err := m.Enforce("alice", "/api/*", "*")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected alice to be allowed with file adapter")
	}
}

func TestFileAdapter_MissingPath(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type": "file",
			// path intentionally omitted
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail when adapter.path is missing")
	}
}

// --- polling watcher tests ---

func TestPollingWatcher_StartStop(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/api/data", "GET"}},
		[][]string{{"alice", "admin"}},
	)

	// Override watcher config to use a short interval.
	m.config.Watcher = watcherConfig{
		Type:     "polling",
		Interval: 50 * time.Millisecond,
	}

	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Let at least one reload tick fire.
	time.Sleep(120 * time.Millisecond)

	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Ensure enforcement still works after stop.
	allowed, err := m.Enforce("alice", "/api/data", "GET")
	if err != nil {
		t.Fatalf("Enforce after stop: %v", err)
	}
	if !allowed {
		t.Error("expected alice to still be allowed after watcher stop")
	}
}

func TestPollingWatcher_StopBeforeStart(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/", "GET"}},
		nil,
	)
	// Stop without Start should be a no-op.
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop without Start: %v", err)
	}
}

func TestPollingWatcher_ReloadsPolicy(t *testing.T) {
	// Use an in-memory module but verify that LoadPolicy is being called
	// by checking that manually added policies are visible after a reload.
	m := buildModule(t,
		[][]string{{"viewer", "/news", "GET"}},
		nil,
	)
	m.config.Watcher = watcherConfig{
		Type:     "polling",
		Interval: 30 * time.Millisecond,
	}

	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop(ctx) }()

	// Directly add a policy to the underlying adapter (bypasses enforcer cache).
	// The polling goroutine should call LoadPolicy which re-reads the adapter.
	_, err := m.AddPolicy([]string{"editor", "/news", "POST"})
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// Give at least two ticks for the policy to be reloaded.
	time.Sleep(100 * time.Millisecond)

	allowed, err := m.Enforce("editor", "/news", "POST")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected editor to be allowed POST /news after polling reload")
	}
}

// --- GORM adapter (SQLite in-memory) tests ---

func TestGORMAdapter_SQLite(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":   "gorm",
			"driver": "sqlite3",
			"dsn":    ":memory:",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init with gorm/sqlite: %v", err)
	}

	// Fresh DB has no policies.
	allowed, err := m.Enforce("alice", "/api", "GET")
	if err != nil {
		t.Fatalf("Enforce on empty gorm DB: %v", err)
	}
	if allowed {
		t.Error("expected no access on empty gorm policy store")
	}

	// Add a policy dynamically.
	if _, err := m.AddPolicy([]string{"alice", "/api", "GET"}); err != nil {
		t.Fatalf("AddPolicy (gorm): %v", err)
	}

	allowed, err = m.Enforce("alice", "/api", "GET")
	if err != nil {
		t.Fatalf("Enforce after AddPolicy (gorm): %v", err)
	}
	if !allowed {
		t.Error("expected alice to be allowed GET /api after AddPolicy in gorm")
	}
}

func TestGORMAdapter_UnknownDriver(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":   "gorm",
			"driver": "oracle",
			"dsn":    "whatever",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail for unknown gorm driver")
	}
}

func TestGORMAdapter_MissingDSN(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":   "gorm",
			"driver": "sqlite3",
			// dsn omitted
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail when adapter.dsn is missing")
	}
}

// --- Option A: tenant-filter GORM tests ---

// TestGORMAdapter_FilterField_InvalidField checks that an invalid filter_field
// is rejected at adapter creation time.
func TestGORMAdapter_FilterField_InvalidField(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          ":memory:",
			"filter_field": "not_a_column", // invalid
			"filter_value": "tenant_a",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail for invalid filter_field")
	}
}

// TestGORMAdapter_FilterField_PartialConfig checks that specifying only one of
// filter_field / filter_value is rejected; both must be set or neither.
func TestGORMAdapter_FilterField_PartialConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		field  string
		value  string
	}{
		{"field only", "v0", ""},
		{"value only", "", "tenant_a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newCasbinModule("authz", map[string]any{
				"model": testModel,
				"adapter": map[string]any{
					"type":         "gorm",
					"driver":       "sqlite3",
					"dsn":          ":memory:",
					"filter_field": tc.field,
					"filter_value": tc.value,
				},
			})
			if err != nil {
				t.Fatalf("newCasbinModule: %v", err)
			}
			if err := m.Init(); err == nil {
				t.Error("expected Init to fail for partial filter config")
			}
		})
	}
}

// TestGORMAdapter_InvalidTableName checks that a table name with characters
// unsafe for use as a raw SQL identifier is rejected at Init time.
func TestGORMAdapter_InvalidTableName(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":       "gorm",
			"driver":     "sqlite3",
			"dsn":        ":memory:",
			"table_name": `casbin_rule"; DROP TABLE casbin_rule; --`, // injection attempt
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail for unsafe table name")
	}
}

// TestGORMAdapter_TenantFilter demonstrates Option A: two modules share the
// same SQLite file-based database but each only loads/manages its own rows,
// identified by the value stored in v0 (the "tenant" column).
func TestGORMAdapter_TenantFilter(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + dir + "/authz.db"

	// Build a shared multi-tenant model where v0 holds the tenant.
	// Policy line:  p, <tenant>, <role>, <obj>, <act>
	// Matcher:      g(r.sub, p.sub, p.v0) && p.v0 == r.dom && r.obj == p.obj ...
	// For simplicity we reuse testModel (sub, obj, act) and put tenant in v0.
	// We seed the DB directly via a plain (no-filter) adapter first.

	// --- seed phase: populate both tenants' rows ---
	seed, err := newCasbinModule("seed", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":   "gorm",
			"driver": "sqlite3",
			"dsn":    dsn,
		},
	})
	if err != nil {
		t.Fatalf("seed newCasbinModule: %v", err)
	}
	if err := seed.Init(); err != nil {
		t.Fatalf("seed Init: %v", err)
	}
	// tenant_a policy: alice → admin → GET /api
	if _, err := seed.AddPolicy([]string{"tenant_a", "/api", "GET"}); err != nil {
		t.Fatalf("seed AddPolicy tenant_a: %v", err)
	}
	// tenant_b policy: bob → admin → POST /data
	if _, err := seed.AddPolicy([]string{"tenant_b", "/data", "POST"}); err != nil {
		t.Fatalf("seed AddPolicy tenant_b: %v", err)
	}

	// --- tenant_a module: filter on v0 = "tenant_a" ---
	modA, err := newCasbinModule("authz_a", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          dsn,
			"filter_field": "v0",
			"filter_value": "tenant_a",
		},
	})
	if err != nil {
		t.Fatalf("modA newCasbinModule: %v", err)
	}
	if err := modA.Init(); err != nil {
		t.Fatalf("modA Init: %v", err)
	}

	// tenant_a can access /api GET
	if ok, err := modA.Enforce("tenant_a", "/api", "GET"); err != nil || !ok {
		t.Errorf("tenant_a should be allowed GET /api: ok=%v err=%v", ok, err)
	}
	// tenant_b's policy is NOT loaded into modA
	if ok, err := modA.Enforce("tenant_b", "/data", "POST"); err != nil || ok {
		t.Errorf("tenant_b policy must not be visible in tenant_a module: ok=%v err=%v", ok, err)
	}

	// --- tenant_b module: filter on v0 = "tenant_b" ---
	modB, err := newCasbinModule("authz_b", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          dsn,
			"filter_field": "v0",
			"filter_value": "tenant_b",
		},
	})
	if err != nil {
		t.Fatalf("modB newCasbinModule: %v", err)
	}
	if err := modB.Init(); err != nil {
		t.Fatalf("modB Init: %v", err)
	}

	// tenant_b can access /data POST
	if ok, err := modB.Enforce("tenant_b", "/data", "POST"); err != nil || !ok {
		t.Errorf("tenant_b should be allowed POST /data: ok=%v err=%v", ok, err)
	}
	// tenant_a's policy is NOT loaded into modB
	if ok, err := modB.Enforce("tenant_a", "/api", "GET"); err != nil || ok {
		t.Errorf("tenant_a policy must not be visible in tenant_b module: ok=%v err=%v", ok, err)
	}
}

// TestGORMAdapter_TenantFilter_MutationIsolation verifies that AddPolicy and
// RemovePolicy on a filtered module only affect that tenant's rows and do not
// corrupt other tenants' data.
func TestGORMAdapter_TenantFilter_MutationIsolation(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + dir + "/authz.db"

	// Seed shared DB.
	seed, err := newCasbinModule("seed", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":   "gorm",
			"driver": "sqlite3",
			"dsn":    dsn,
		},
	})
	if err != nil {
		t.Fatalf("seed newCasbinModule: %v", err)
	}
	if err := seed.Init(); err != nil {
		t.Fatalf("seed Init: %v", err)
	}
	if _, err := seed.AddPolicy([]string{"tenant_b", "/reports", "GET"}); err != nil {
		t.Fatalf("seed AddPolicy: %v", err)
	}

	// Filtered module for tenant_a.
	modA, err := newCasbinModule("authz_a", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          dsn,
			"filter_field": "v0",
			"filter_value": "tenant_a",
		},
	})
	if err != nil {
		t.Fatalf("modA newCasbinModule: %v", err)
	}
	if err := modA.Init(); err != nil {
		t.Fatalf("modA Init: %v", err)
	}

	// Add a policy for tenant_a.
	if _, err := modA.AddPolicy([]string{"tenant_a", "/metrics", "GET"}); err != nil {
		t.Fatalf("modA AddPolicy: %v", err)
	}
	if ok, err := modA.Enforce("tenant_a", "/metrics", "GET"); err != nil || !ok {
		t.Errorf("tenant_a should be allowed GET /metrics: ok=%v err=%v", ok, err)
	}

	// Remove tenant_a's policy.
	if _, err := modA.RemovePolicy([]string{"tenant_a", "/metrics", "GET"}); err != nil {
		t.Fatalf("modA RemovePolicy: %v", err)
	}
	if ok, err := modA.Enforce("tenant_a", "/metrics", "GET"); err != nil || ok {
		t.Errorf("tenant_a /metrics should be denied after removal: ok=%v err=%v", ok, err)
	}

	// Verify tenant_b's row is still intact in the shared DB.
	modB, err := newCasbinModule("authz_b", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          dsn,
			"filter_field": "v0",
			"filter_value": "tenant_b",
		},
	})
	if err != nil {
		t.Fatalf("modB newCasbinModule: %v", err)
	}
	if err := modB.Init(); err != nil {
		t.Fatalf("modB Init: %v", err)
	}
	if ok, err := modB.Enforce("tenant_b", "/reports", "GET"); err != nil || !ok {
		t.Errorf("tenant_b /reports should still be allowed: ok=%v err=%v", ok, err)
	}
}

// TestGORMAdapter_TenantFilter_CrossTenantWriteRejected verifies that AddPolicy
// and RemovePolicy reject rules whose tenant field does not match the adapter's
// filter value, preventing accidental cross-tenant writes.
func TestGORMAdapter_TenantFilter_CrossTenantWriteRejected(t *testing.T) {
	m, err := newCasbinModule("authz_a", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":         "gorm",
			"driver":       "sqlite3",
			"dsn":          ":memory:",
			"filter_field": "v0",
			"filter_value": "tenant_a",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Attempting to add a rule for a different tenant must be rejected.
	if _, err := m.AddPolicy([]string{"tenant_b", "/api", "GET"}); err == nil {
		t.Error("expected AddPolicy to fail for cross-tenant rule (tenant_b via tenant_a adapter)")
	}

	// Attempting to remove a rule for a different tenant must also be rejected.
	if _, err := m.RemovePolicy([]string{"tenant_b", "/api", "GET"}); err == nil {
		t.Error("expected RemovePolicy to fail for cross-tenant rule")
	}
}

// TestGORMAdapter_PerTenantTable verifies that two modules configured with
// different table names have completely independent policy stores.
func TestGORMAdapter_PerTenantTable(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + dir + "/authz.db"

	makeModule := func(name, table string) *CasbinModule {
		t.Helper()
		m, err := newCasbinModule(name, map[string]any{
			"model": testModel,
			"adapter": map[string]any{
				"type":       "gorm",
				"driver":     "sqlite3",
				"dsn":        dsn,
				"table_name": table,
			},
		})
		if err != nil {
			t.Fatalf("newCasbinModule %s: %v", name, err)
		}
		if err := m.Init(); err != nil {
			t.Fatalf("Init %s: %v", name, err)
		}
		return m
	}

	modA := makeModule("authz_a", "casbin_rule_tenant_a")
	modB := makeModule("authz_b", "casbin_rule_tenant_b")

	// Add distinct policies to each table.
	if _, err := modA.AddPolicy([]string{"alice", "/a", "GET"}); err != nil {
		t.Fatalf("modA AddPolicy: %v", err)
	}
	if _, err := modB.AddPolicy([]string{"bob", "/b", "POST"}); err != nil {
		t.Fatalf("modB AddPolicy: %v", err)
	}

	// Each module only sees its own policies.
	if ok, err := modA.Enforce("alice", "/a", "GET"); err != nil || !ok {
		t.Errorf("alice should be allowed GET /a in tenant_a: ok=%v err=%v", ok, err)
	}
	if ok, err := modA.Enforce("bob", "/b", "POST"); err != nil || ok {
		t.Errorf("bob's policy must not exist in tenant_a table: ok=%v err=%v", ok, err)
	}
	if ok, err := modB.Enforce("bob", "/b", "POST"); err != nil || !ok {
		t.Errorf("bob should be allowed POST /b in tenant_b: ok=%v err=%v", ok, err)
	}
	if ok, err := modB.Enforce("alice", "/a", "GET"); err != nil || ok {
		t.Errorf("alice's policy must not exist in tenant_b table: ok=%v err=%v", ok, err)
	}
}

// TestGORMAdapter_TableNameTemplate verifies that a Go template in table_name
// is resolved using the Tenant config field (Option B).
func TestGORMAdapter_TableNameTemplate(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + dir + "/authz.db"

	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":       "gorm",
			"driver":     "sqlite3",
			"dsn":        dsn,
			"table_name": "casbin_rule_{{.Tenant}}",
			"tenant":     "acme_corp",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Add and enforce a policy – proves the table was created and is usable.
	if _, err := m.AddPolicy([]string{"alice", "/dashboard", "GET"}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if ok, err := m.Enforce("alice", "/dashboard", "GET"); err != nil || !ok {
		t.Errorf("alice should be allowed GET /dashboard: ok=%v err=%v", ok, err)
	}
}

// TestGORMAdapter_TableNameTemplate_Invalid checks that an invalid template
// expression is rejected at Init time.
func TestGORMAdapter_TableNameTemplate_Invalid(t *testing.T) {
	m, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":       "gorm",
			"driver":     "sqlite3",
			"dsn":        ":memory:",
			"table_name": "casbin_rule_{{.Unclosed", // broken template
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail for invalid table_name template")
	}
}



func TestInMemoryAdapter_AddRemovePolicy(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/api", "GET"}},
		[][]string{{"alice", "admin"}},
	)

	// Add a new policy.
	added, err := m.AddPolicy([]string{"editor", "/api/posts", "POST"})
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if !added {
		t.Error("expected AddPolicy to return true")
	}

	// bob is editor → can now POST /api/posts
	_, _ = m.AddGroupingPolicy([]string{"bob", "editor"})

	allowed, err := m.Enforce("bob", "/api/posts", "POST")
	if err != nil {
		t.Fatalf("Enforce after AddPolicy: %v", err)
	}
	if !allowed {
		t.Error("expected bob to be allowed POST /api/posts after AddPolicy")
	}

	// Remove the policy.
	removed, err := m.RemovePolicy([]string{"editor", "/api/posts", "POST"})
	if err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if !removed {
		t.Error("expected RemovePolicy to return true")
	}

	// bob should no longer be allowed.
	allowed, err = m.Enforce("bob", "/api/posts", "POST")
	if err != nil {
		t.Fatalf("Enforce after RemovePolicy: %v", err)
	}
	if allowed {
		t.Error("expected bob to be denied after RemovePolicy")
	}
}

func TestInMemoryAdapter_AddGroupingPolicy(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/admin", "GET"}},
		nil,
	)

	// dave has no role → denied
	allowed, err := m.Enforce("dave", "/admin", "GET")
	if err != nil {
		t.Fatalf("Enforce before AddGroupingPolicy: %v", err)
	}
	if allowed {
		t.Error("expected dave to be denied before role assignment")
	}

	// Assign admin role to dave.
	if _, err := m.AddGroupingPolicy([]string{"dave", "admin"}); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	allowed, err = m.Enforce("dave", "/admin", "GET")
	if err != nil {
		t.Fatalf("Enforce after AddGroupingPolicy: %v", err)
	}
	if !allowed {
		t.Error("expected dave to be allowed after AddGroupingPolicy")
	}

	// Remove the assignment.
	if _, err := m.RemoveGroupingPolicy([]string{"dave", "admin"}); err != nil {
		t.Fatalf("RemoveGroupingPolicy: %v", err)
	}

	allowed, err = m.Enforce("dave", "/admin", "GET")
	if err != nil {
		t.Fatalf("Enforce after RemoveGroupingPolicy: %v", err)
	}
	if allowed {
		t.Error("expected dave to be denied after RemoveGroupingPolicy")
	}
}

func TestInMemoryAdapter_NotInitialised_AddPolicy(t *testing.T) {
	m := &CasbinModule{name: "uninit"}
	_, err := m.AddPolicy([]string{"x", "/y", "z"})
	if err == nil {
		t.Error("expected error from uninitialised module AddPolicy")
	}
}

func TestInMemoryAdapter_NotInitialised_RemovePolicy(t *testing.T) {
	m := &CasbinModule{name: "uninit"}
	_, err := m.RemovePolicy([]string{"x", "/y", "z"})
	if err == nil {
		t.Error("expected error from uninitialised module RemovePolicy")
	}
}
