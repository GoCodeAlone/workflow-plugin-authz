package internal

import (
	"context"
	"testing"
)

// --- step.authz_add_policy tests ---

func TestAuthzAddPolicyStep_AddsRule(t *testing.T) {
	mod := buildModule(t,
		[][]string{{"admin", "/api", "GET"}},
		[][]string{{"alice", "admin"}},
	)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzAddPolicyStep("add-step", map[string]any{
		"rule": []any{"editor", "/api/posts", "POST"},
	})
	if err != nil {
		t.Fatalf("newAuthzAddPolicyStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["authz_policy_added"] != true {
		t.Errorf("expected authz_policy_added=true, got %v", result.Output["authz_policy_added"])
	}

	// Assign bob to editor and check enforcement.
	if _, err := mod.AddGroupingPolicy([]string{"bob", "editor"}); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}
	allowed, err := mod.Enforce("bob", "/api/posts", "POST")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected bob to be allowed POST /api/posts after step.authz_add_policy")
	}
}

func TestAuthzAddPolicyStep_TemplateRule(t *testing.T) {
	mod := buildModule(t, nil, nil)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzAddPolicyStep("add-tmpl", map[string]any{
		"rule": []any{"{{.role}}", "{{.resource}}", "{{.method}}"},
	})
	if err != nil {
		t.Fatalf("newAuthzAddPolicyStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(),
		map[string]any{"role": "viewer", "resource": "/news", "method": "GET"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = result

	allowed, err := mod.Enforce("viewer", "/news", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected viewer to be allowed GET /news after template add_policy")
	}
}

func TestAuthzAddPolicyStep_MissingRule(t *testing.T) {
	_, err := newAuthzAddPolicyStep("bad", map[string]any{})
	if err == nil {
		t.Error("expected error for missing rule")
	}
}

func TestAuthzAddPolicyStep_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzAddPolicyStep("no-mod", map[string]any{
		"rule": []any{"admin", "/api", "GET"},
	})
	if err != nil {
		t.Fatalf("newAuthzAddPolicyStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

// --- step.authz_remove_policy tests ---

func TestAuthzRemovePolicyStep_RemovesRule(t *testing.T) {
	mod := buildModule(t,
		[][]string{
			{"admin", "/api", "GET"},
			{"editor", "/api/posts", "POST"},
		},
		[][]string{
			{"alice", "admin"},
			{"bob", "editor"},
		},
	)
	reg := &testRegistry{mod: mod}

	// Bob should currently be allowed.
	allowed, _ := mod.Enforce("bob", "/api/posts", "POST")
	if !allowed {
		t.Fatal("pre-condition: bob should be allowed POST /api/posts")
	}

	s, err := newAuthzRemovePolicyStep("remove-step", map[string]any{
		"rule": []any{"editor", "/api/posts", "POST"},
	})
	if err != nil {
		t.Fatalf("newAuthzRemovePolicyStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["authz_policy_removed"] != true {
		t.Errorf("expected authz_policy_removed=true, got %v", result.Output["authz_policy_removed"])
	}

	// Bob should no longer be allowed.
	allowed, err = mod.Enforce("bob", "/api/posts", "POST")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed {
		t.Error("expected bob to be denied POST /api/posts after remove_policy")
	}
}

func TestAuthzRemovePolicyStep_TemplateRule(t *testing.T) {
	mod := buildModule(t,
		[][]string{{"viewer", "/news", "GET"}},
		nil,
	)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzRemovePolicyStep("remove-tmpl", map[string]any{
		"rule": []any{"{{.role}}", "{{.resource}}", "{{.method}}"},
	})
	if err != nil {
		t.Fatalf("newAuthzRemovePolicyStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(),
		map[string]any{"role": "viewer", "resource": "/news", "method": "GET"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	allowed, _ := mod.Enforce("viewer", "/news", "GET")
	if allowed {
		t.Error("expected viewer to be denied after template remove_policy")
	}
}

func TestAuthzRemovePolicyStep_MissingRule(t *testing.T) {
	_, err := newAuthzRemovePolicyStep("bad", map[string]any{})
	if err == nil {
		t.Error("expected error for missing rule")
	}
}

func TestAuthzRemovePolicyStep_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzRemovePolicyStep("no-mod", map[string]any{
		"rule": []any{"admin", "/api", "GET"},
	})
	if err != nil {
		t.Fatalf("newAuthzRemovePolicyStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

// --- step.authz_role_assign tests ---

func TestAuthzRoleAssignStep_Add(t *testing.T) {
	mod := buildModule(t,
		[][]string{{"admin", "/admin", "GET"}},
		nil,
	)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzRoleAssignStep("assign-add", map[string]any{
		"action":      "add",
		"assignments": []any{[]any{"dave", "admin"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute add: %v", err)
	}
	if result.Output["authz_role_action"] != "add" {
		t.Errorf("unexpected action: %v", result.Output["authz_role_action"])
	}

	allowed, err := mod.Enforce("dave", "/admin", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected dave to be allowed GET /admin after role assign add")
	}
}

func TestAuthzRoleAssignStep_Remove(t *testing.T) {
	mod := buildModule(t,
		[][]string{{"admin", "/admin", "GET"}},
		[][]string{{"dave", "admin"}},
	)
	reg := &testRegistry{mod: mod}

	// Pre-condition: dave is allowed.
	allowed, _ := mod.Enforce("dave", "/admin", "GET")
	if !allowed {
		t.Fatal("pre-condition: dave should be allowed before role remove")
	}

	s, err := newAuthzRoleAssignStep("assign-remove", map[string]any{
		"action":      "remove",
		"assignments": []any{[]any{"dave", "admin"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute remove: %v", err)
	}

	allowed, err = mod.Enforce("dave", "/admin", "GET")
	if err != nil {
		t.Fatalf("Enforce after remove: %v", err)
	}
	if allowed {
		t.Error("expected dave to be denied after role assign remove")
	}
}

func TestAuthzRoleAssignStep_TemplateAssignment(t *testing.T) {
	mod := buildModule(t,
		[][]string{{"superuser", "/root", "GET"}},
		nil,
	)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzRoleAssignStep("assign-tmpl", map[string]any{
		"action":      "add",
		"assignments": []any{[]any{"{{.user}}", "superuser"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(),
		map[string]any{"user": "eve"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("Execute template assign: %v", err)
	}

	allowed, err := mod.Enforce("eve", "/root", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected eve to be allowed GET /root after template role assign")
	}
}

func TestAuthzRoleAssignStep_InvalidAction(t *testing.T) {
	_, err := newAuthzRoleAssignStep("bad-action", map[string]any{
		"action":      "grant", // invalid
		"assignments": []any{[]any{"user", "role"}},
	})
	if err == nil {
		t.Error("expected error for invalid action")
	}
}

func TestAuthzRoleAssignStep_MissingAssignments(t *testing.T) {
	_, err := newAuthzRoleAssignStep("no-assign", map[string]any{
		"action": "add",
	})
	if err == nil {
		t.Error("expected error for missing assignments")
	}
}

func TestAuthzRoleAssignStep_AssignmentTooShort(t *testing.T) {
	_, err := newAuthzRoleAssignStep("short-assign", map[string]any{
		"action":      "add",
		"assignments": []any{[]any{"only-one"}},
	})
	if err == nil {
		t.Error("expected error for assignment with < 2 elements")
	}
}

func TestAuthzRoleAssignStep_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzRoleAssignStep("no-mod", map[string]any{
		"action":      "add",
		"assignments": []any{[]any{"user", "role"}},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

func TestAuthzRoleAssignStep_MultipleAssignments(t *testing.T) {
	mod := buildModule(t,
		[][]string{
			{"admin", "/admin", "GET"},
			{"editor", "/posts", "POST"},
		},
		nil,
	)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzRoleAssignStep("multi-assign", map[string]any{
		"action": "add",
		"assignments": []any{
			[]any{"frank", "admin"},
			[]any{"frank", "editor"},
		},
	})
	if err != nil {
		t.Fatalf("newAuthzRoleAssignStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	a1, _ := mod.Enforce("frank", "/admin", "GET")
	a2, _ := mod.Enforce("frank", "/posts", "POST")
	if !a1 || !a2 {
		t.Errorf("expected frank to have both roles; admin=%v editor=%v", a1, a2)
	}
}
