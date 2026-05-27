package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestAuthzDecisionStep(t *testing.T) {
	ctx := context.Background()
	mod := rbacTestModule(t, nil, nil)
	scope := &contracts.ScopeDeclaration{Name: "admin:authz.roles:update", Context: "admin", Resource: "authz.roles", Actions: []string{"update"}}
	if err := mod.DeclareScopes(ctx, []*contracts.ScopeDeclaration{scope}); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
	if err := mod.UpsertRole(ctx, RoleScopeGrant{Role: "admin", Context: "admin", Scopes: []string{scope.GetName()}}); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	if err := mod.AssignRole(ctx, SubjectRoleAssignment{Subject: "admin@tailnet", Role: "admin", Context: "admin"}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	step, err := newAuthzDecisionStep("gate", map[string]any{
		"provider": "casbin",
		"mode":     "rbac",
		"subject":  "{{.user}}",
		"context":  "admin",
		"scope":    scope.GetName(),
	})
	if err != nil {
		t.Fatalf("newAuthzDecisionStep: %v", err)
	}
	step.registry = &testRegistry{mod: mod}
	result, err := step.Execute(ctx, nil, nil, map[string]any{"user": "admin@tailnet"}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != true || result.Output["mode"] != "rbac" {
		t.Fatalf("decision output = %#v", result.Output)
	}
}

func TestAuthzRequireCapabilitiesStep(t *testing.T) {
	step, err := newAuthzRequireCapabilitiesStep("requirements", map[string]any{
		"provider": "keto",
		"module":   "keto",
		"requirements": []any{
			map[string]any{"mode": "rebac", "operations": []any{"check", "manage_relations"}},
		},
	})
	if err != nil {
		t.Fatalf("newAuthzRequireCapabilitiesStep: %v", err)
	}
	step.registry = &testCapabilityRegistry{providers: map[string]AuthzProvider{"keto": &KetoModule{name: "keto"}}}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["health"] != "ok" {
		t.Fatalf("require capabilities output = %#v", result.Output)
	}
}
