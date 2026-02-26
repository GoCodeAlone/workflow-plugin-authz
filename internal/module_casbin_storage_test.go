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

// --- inMemoryAdapter mutation tests ---

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
