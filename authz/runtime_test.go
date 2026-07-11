package authz

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const runtimeTestModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.sub == p.sub || g(r.sub, p.sub)) && r.obj == p.obj && r.act == p.act
`

func TestRuntimeRequiresExactlyOneSource(t *testing.T) {
	t.Parallel()

	validStorage := &StorageConfig{
		Driver:        "postgres",
		DSN:           "postgres://example.invalid/authz",
		MigrationMode: MigrationModeValidate,
	}
	validSeed := &SeedConfig{}

	for _, tt := range []struct {
		name string
		cfg  RuntimeConfig
	}{
		{name: "missing model", cfg: RuntimeConfig{Seed: validSeed}},
		{name: "invalid model", cfg: RuntimeConfig{Model: "not a casbin model", Seed: validSeed}},
		{name: "missing source", cfg: RuntimeConfig{Model: runtimeTestModel}},
		{name: "both sources", cfg: RuntimeConfig{Model: runtimeTestModel, Storage: validStorage, Seed: validSeed}},
		{name: "storage missing driver", cfg: RuntimeConfig{Model: runtimeTestModel, Storage: &StorageConfig{DSN: "dsn", MigrationMode: MigrationModeValidate}}},
		{name: "storage missing dsn", cfg: RuntimeConfig{Model: runtimeTestModel, Storage: &StorageConfig{Driver: "postgres", MigrationMode: MigrationModeValidate}}},
		{name: "storage missing mode", cfg: RuntimeConfig{Model: runtimeTestModel, Storage: &StorageConfig{Driver: "postgres", DSN: "dsn"}}},
		{name: "policy has extra dimension", cfg: RuntimeConfig{Model: runtimeTestModel, Seed: &SeedConfig{Policies: [][]string{{"admin", "status", "read", "extra"}}}}},
		{name: "role has extra dimension", cfg: RuntimeConfig{Model: runtimeTestModel, Seed: &SeedConfig{RoleAssignments: [][]string{{"alice", "admin", "extra"}}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRuntime(t.Context(), tt.cfg); err == nil {
				t.Fatalf("NewRuntime(%s) succeeded", tt.name)
			}
		})
	}
}

func TestRuntimeConstructionHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := NewRuntime(ctx, RuntimeConfig{Model: runtimeTestModel, Seed: &SeedConfig{}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NewRuntime(canceled) error = %v, want context.Canceled", err)
	}
}

func TestRuntimePersistentErrorsAreSanitized(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(t.Context(), RuntimeConfig{
		Model: runtimeTestModel,
		Storage: &StorageConfig{
			Driver:        "secret-driver",
			DSN:           "secret-dsn",
			MigrationMode: MigrationModeAuto,
		},
	})
	if err == nil || err.Error() != "authz runtime: persistent storage unavailable" {
		t.Fatalf("unsupported driver error = %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("persistent error exposed config: %v", err)
	}

	_, err = NewRuntime(t.Context(), RuntimeConfig{
		Model: runtimeTestModel,
		Storage: &StorageConfig{
			Driver:        "sqlite3",
			DSN:           filepath.Join(t.TempDir(), "missing-schema.db"),
			MigrationMode: MigrationModeValidate,
		},
	})
	if err == nil || err.Error() != "authz storage schema v1 table" {
		t.Fatalf("schema validation error = %v, want sanitized table category", err)
	}
}

func TestRuntimeSeededMemoryDecisionsPoliciesAndSnapshot(t *testing.T) {
	t.Parallel()

	seed := &SeedConfig{Policies: [][]string{
		{"tenant_admin", "admin:profile", "read"},
		{"super_admin", "admin:status", "read"},
	}, RoleAssignments: [][]string{{"alice", "super_admin"}}}
	runtime, err := NewRuntime(t.Context(), RuntimeConfig{Model: runtimeTestModel, Seed: seed})
	if err != nil {
		t.Fatalf("NewRuntime(): %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	seed.Policies[1][0] = "mutated"
	seed.Policies = append(seed.Policies, []string{"mutated", "*", "*"})
	seed.RoleAssignments[0][1] = "mutated"

	allowed, err := runtime.Decide(t.Context(), DecisionRequest{Subject: "super_admin", Object: "admin:status", Action: "read"})
	if err != nil {
		t.Fatalf("Decide(allow): %v", err)
	}
	if !allowed.Allowed {
		t.Fatal("super_admin decision denied")
	}
	roleAllowed, err := runtime.Decide(t.Context(), DecisionRequest{Subject: "alice", Object: "admin:status", Action: "read"})
	if err != nil || !roleAllowed.Allowed {
		t.Fatalf("direct role assignment decision = %#v, %v", roleAllowed, err)
	}
	denied, err := runtime.Decide(t.Context(), DecisionRequest{Subject: "tenant_admin", Object: "admin:status", Action: "read"})
	if err != nil {
		t.Fatalf("Decide(deny): %v", err)
	}
	if denied.Allowed {
		t.Fatal("tenant_admin decision allowed")
	}

	want := []PolicyRule{
		{Subject: "super_admin", Object: "admin:status", Action: "read"},
		{Subject: "tenant_admin", Object: "admin:profile", Action: "read"},
	}
	got, err := runtime.Policies(t.Context())
	if err != nil {
		t.Fatalf("Policies(): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Policies() = %#v, want %#v", got, want)
	}
	got[0].Subject = "caller-mutated"
	again, err := runtime.Policies(t.Context())
	if err != nil {
		t.Fatalf("Policies() again: %v", err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("Policies() exposed mutable snapshot: %#v", again)
	}
	if health := runtime.Health(t.Context()); health.Status != HealthReady {
		t.Fatalf("memory Health() = %#v, want ready", health)
	}
}

func TestRuntimeHealthDoesNotGateLoadedSnapshot(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(t.Context(), RuntimeConfig{
		Model: runtimeTestModel,
		Seed:  &SeedConfig{Policies: [][]string{{"admin", "status", "read"}}},
	})
	if err != nil {
		t.Fatalf("NewRuntime(): %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	runtime.persistent = true
	runtime.ping = func(context.Context) error { return errors.New("database unavailable") }
	if health := runtime.Health(t.Context()); health.Status != HealthDegraded {
		t.Fatalf("Health() = %#v, want degraded", health)
	}
	decision, err := runtime.Decide(t.Context(), DecisionRequest{Subject: "admin", Object: "status", Action: "read"})
	if err != nil || !decision.Allowed {
		t.Fatalf("Decide() after degraded health = %#v, %v", decision, err)
	}

	runtime.ping = func(ctx context.Context) error { return ctx.Err() }
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if health := runtime.Health(canceled); health.Status != HealthUnknown {
		t.Fatalf("Health(canceled) = %#v, want unknown", health)
	}
	runtime.ping = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	bounded, cancelBounded := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelBounded()
	started := time.Now()
	if health := runtime.Health(bounded); health.Status != HealthUnknown {
		t.Fatalf("Health(deadline) = %#v, want unknown", health)
	}
	if time.Since(started) > time.Second {
		t.Fatal("Health ignored the caller deadline")
	}
	if health := runtime.Health(t.Context()); health.Status != HealthDegraded {
		t.Fatalf("Health(internal timeout) = %#v, want degraded", health)
	}
}

func TestRuntimeCloseIsIdempotentAndRaceSafe(t *testing.T) {
	runtime, err := NewRuntime(t.Context(), RuntimeConfig{
		Model: runtimeTestModel,
		Seed:  &SeedConfig{Policies: [][]string{{"admin", "status", "read"}}},
	})
	if err != nil {
		t.Fatalf("NewRuntime(): %v", err)
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				_, err := runtime.Decide(context.Background(), DecisionRequest{Subject: "admin", Object: "status", Action: "read"})
				if err != nil && !errors.Is(err, ErrRuntimeClosed) {
					t.Errorf("Decide() error = %v", err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	wg.Wait()

	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
	if _, err := runtime.Decide(t.Context(), DecisionRequest{}); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Decide() after Close error = %v, want ErrRuntimeClosed", err)
	}
	if _, err := runtime.Policies(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Policies() after Close error = %v, want ErrRuntimeClosed", err)
	}
	if health := runtime.Health(t.Context()); health.Status != HealthUnknown {
		t.Fatalf("Health() after Close = %#v, want unknown", health)
	}
}
