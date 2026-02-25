package internal

import (
	"context"
	"testing"
)

const testModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func buildModule(t *testing.T, policies, roleAssignments [][]string) *CasbinModule {
	t.Helper()

	rawPolicies := make([]any, len(policies))
	for i, p := range policies {
		row := make([]any, len(p))
		for j, s := range p {
			row[j] = s
		}
		rawPolicies[i] = row
	}

	rawAssignments := make([]any, len(roleAssignments))
	for i, a := range roleAssignments {
		row := make([]any, len(a))
		for j, s := range a {
			row[j] = s
		}
		rawAssignments[i] = row
	}

	m, err := newCasbinModule("authz", map[string]any{
		"model":           testModel,
		"policies":        rawPolicies,
		"roleAssignments": rawAssignments,
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("CasbinModule.Init: %v", err)
	}
	return m
}

func TestCasbinModule_EnforceAllow(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/api/posts", "GET"}},
		[][]string{{"alice", "admin"}},
	)

	allowed, err := m.Enforce("alice", "/api/posts", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected alice to be allowed GET /api/posts")
	}
}

func TestCasbinModule_EnforceDeny(t *testing.T) {
	m := buildModule(t,
		[][]string{{"viewer", "/api/posts", "GET"}},
		[][]string{{"bob", "viewer"}},
	)

	// bob can GET but not DELETE
	allowed, err := m.Enforce("bob", "/api/posts", "DELETE")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed {
		t.Error("expected bob to be denied DELETE /api/posts")
	}
}

func TestCasbinModule_RoleHierarchy(t *testing.T) {
	m := buildModule(t,
		[][]string{
			{"admin", "/api/*", "*"},
			{"viewer", "/api/posts", "GET"},
		},
		[][]string{
			{"alice", "admin"},
			{"carol", "viewer"},
		},
	)

	// alice has admin → can do anything
	for _, tc := range []struct {
		obj string
		act string
	}{
		{"/api/*", "*"},
	} {
		ok, err := m.Enforce("alice", tc.obj, tc.act)
		if err != nil {
			t.Fatalf("Enforce alice %s %s: %v", tc.obj, tc.act, err)
		}
		if !ok {
			t.Errorf("expected alice allowed %s %s", tc.obj, tc.act)
		}
	}

	// carol viewer → can GET /api/posts but not DELETE
	okGet, _ := m.Enforce("carol", "/api/posts", "GET")
	if !okGet {
		t.Error("expected carol allowed GET /api/posts")
	}

	okDel, _ := m.Enforce("carol", "/api/posts", "DELETE")
	if okDel {
		t.Error("expected carol denied DELETE /api/posts")
	}
}

func TestCasbinModule_Lifecycle(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/", "GET"}},
		nil,
	)

	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestCasbinModule_InitTwice(t *testing.T) {
	m := buildModule(t,
		[][]string{{"admin", "/api", "GET"}},
		[][]string{{"alice", "admin"}},
	)

	// Second Init should succeed (replaces enforcer).
	if err := m.Init(); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	allowed, err := m.Enforce("alice", "/api", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected alice allowed after second Init")
	}
}

func TestParseCasbinConfig_MissingModel(t *testing.T) {
	_, err := parseCasbinConfig(map[string]any{})
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestParseCasbinConfig_InvalidPolicy(t *testing.T) {
	_, err := parseCasbinConfig(map[string]any{
		"model":    testModel,
		"policies": []any{[]any{"only-two-fields", "/api"}}, // missing act
	})
	if err == nil {
		t.Error("expected error for policy with < 3 elements")
	}
}

func TestParseCasbinConfig_InvalidRoleAssignment(t *testing.T) {
	_, err := parseCasbinConfig(map[string]any{
		"model":           testModel,
		"policies":        []any{},
		"roleAssignments": []any{[]any{"only-one"}}, // missing role
	})
	if err == nil {
		t.Error("expected error for role assignment with < 2 elements")
	}
}

func TestCasbinModule_NotInitialised(t *testing.T) {
	m := &CasbinModule{name: "uninit"}
	_, err := m.Enforce("alice", "/api", "GET")
	if err == nil {
		t.Error("expected error from uninitialised module")
	}
}

func TestNewCasbinModule_InvalidConfig(t *testing.T) {
	_, err := newCasbinModule("bad", map[string]any{
		// model is empty
	})
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestCasbinModule_BadModel(t *testing.T) {
	m, err := newCasbinModule("bad-model", map[string]any{
		"model":    "this is not valid casbin ini",
		"policies": []any{},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err) // parse happens in Init
	}
	if err := m.Init(); err == nil {
		t.Error("expected Init to fail with invalid model")
	}
}
