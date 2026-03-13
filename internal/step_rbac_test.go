package internal

import (
	"context"
	"testing"
)

// rbacTestModule builds a Casbin module with a standard RBAC model.
func rbacTestModule(t *testing.T, policies [][]string, roleAssignments [][]string) *CasbinModule {
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
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && (r.act == p.act || p.act == "*")
`,
		"policies":        rawPolicies,
		"roleAssignments": rawAssignments,
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return m
}

func TestRBAC_RoleAssignment(t *testing.T) {
	mod := rbacTestModule(t,
		[][]string{{"admin", "/api", "GET"}},
		nil,
	)
	reg := &testRegistry{mod: mod}

	// Assign alice to admin role
	s, err := newAuthzRoleAssignStep("assign", map[string]any{
		"action":      "add",
		"assignments": []any{[]any{"alice", "admin"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// alice should now have admin permissions
	allowed, err := mod.Enforce("alice", "/api", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected alice to be allowed after role assignment")
	}
}

func TestRBAC_PermissionCheckGranted(t *testing.T) {
	mod := rbacTestModule(t,
		[][]string{
			{"admin", "/api", "*"},
			{"viewer", "/api", "GET"},
		},
		[][]string{
			{"alice", "admin"},
			{"bob", "viewer"},
		},
	)
	reg := &testRegistry{mod: mod}

	// Admin can do anything
	s := newTestStep(t, map[string]any{
		"object": "/api",
		"action": "DELETE",
	}, reg)
	allowed, stopped := execute(t, s, nil,
		map[string]any{"auth_user_id": "alice"}, nil)
	if !allowed || stopped {
		t.Errorf("expected admin alice to be allowed DELETE; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestRBAC_PermissionCheckDenied(t *testing.T) {
	mod := rbacTestModule(t,
		[][]string{{"viewer", "/api", "GET"}},
		[][]string{{"bob", "viewer"}},
	)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api",
		"action": "DELETE",
	}, reg)
	allowed, stopped := execute(t, s, nil,
		map[string]any{"auth_user_id": "bob"}, nil)
	if allowed || !stopped {
		t.Errorf("expected viewer bob to be denied DELETE; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestRBAC_RoleHierarchy(t *testing.T) {
	// Build module with role hierarchy: admin inherits from editor
	rawPolicies := []any{
		[]any{"admin", "/admin", "*"},
		[]any{"editor", "/posts", "GET"},
		[]any{"editor", "/posts", "POST"},
	}
	rawAssignments := []any{
		[]any{"admin", "editor"}, // admin inherits editor
		[]any{"alice", "admin"},
		[]any{"bob", "editor"},
	}

	m, err := newCasbinModule("authz", map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && (r.act == p.act || p.act == "*")
`,
		"policies":        rawPolicies,
		"roleAssignments": rawAssignments,
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// alice (admin) should inherit editor's permissions
	allowed, _ := m.Enforce("alice", "/posts", "GET")
	if !allowed {
		t.Error("expected admin alice to inherit editor GET /posts")
	}
	allowed, _ = m.Enforce("alice", "/posts", "POST")
	if !allowed {
		t.Error("expected admin alice to inherit editor POST /posts")
	}
	allowed, _ = m.Enforce("alice", "/admin", "*")
	if !allowed {
		t.Error("expected admin alice to access /admin")
	}

	// bob (editor) should NOT have admin permissions
	allowed, _ = m.Enforce("bob", "/admin", "*")
	if allowed {
		t.Error("expected editor bob to be denied /admin")
	}
	// bob should have editor permissions
	allowed, _ = m.Enforce("bob", "/posts", "GET")
	if !allowed {
		t.Error("expected editor bob to have GET /posts")
	}
}

func TestRBAC_RoleRemovalAndRecheck(t *testing.T) {
	mod := rbacTestModule(t,
		[][]string{{"admin", "/api", "GET"}},
		[][]string{{"alice", "admin"}},
	)
	reg := &testRegistry{mod: mod}

	// Verify alice is allowed
	allowed, _ := mod.Enforce("alice", "/api", "GET")
	if !allowed {
		t.Fatal("pre-condition: alice should be allowed")
	}

	// Remove alice from admin role
	s, err := newAuthzRoleAssignStep("unassign", map[string]any{
		"action":      "remove",
		"assignments": []any{[]any{"alice", "admin"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// alice should be denied now
	allowed, _ = mod.Enforce("alice", "/api", "GET")
	if allowed {
		t.Error("expected alice to be denied after role removal")
	}
}
