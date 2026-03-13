package internal

import (
	"context"
	"testing"
)

// abacTestModule builds a Casbin module with an ABAC-style model.
// Policies use subject-attribute, object-attribute, action pattern.
func abacTestModule(t *testing.T, policies [][]string) *CasbinModule {
	t.Helper()

	rawPolicies := make([]any, len(policies))
	for i, p := range policies {
		row := make([]any, len(p))
		for j, s := range p {
			row[j] = s
		}
		rawPolicies[i] = row
	}

	m, err := newCasbinModule("authz", map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`,
		"policies": rawPolicies,
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return m
}

func TestABAC_CheckAllowed(t *testing.T) {
	// Simulate attribute-based: "engineering" department can "read" "code" resources
	mod := abacTestModule(t, [][]string{
		{"engineering", "code", "read"},
	})
	reg := &testRegistry{mod: mod}

	s, err := newAuthzABACCheckStep("check", map[string]any{
		"subject": "engineering",
		"object":  "code",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzABACCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != true {
		t.Errorf("expected allowed=true, got %v", result.Output["allowed"])
	}
}

func TestABAC_CheckDenied_AttributeMismatch(t *testing.T) {
	mod := abacTestModule(t, [][]string{
		{"engineering", "code", "read"},
	})
	reg := &testRegistry{mod: mod}

	// marketing department trying to access code
	s, err := newAuthzABACCheckStep("check", map[string]any{
		"subject": "marketing",
		"object":  "code",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzABACCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != false {
		t.Errorf("expected allowed=false for marketing accessing code, got %v", result.Output["allowed"])
	}
}

func TestABAC_CheckDenied_WrongAction(t *testing.T) {
	mod := abacTestModule(t, [][]string{
		{"engineering", "code", "read"},
	})
	reg := &testRegistry{mod: mod}

	// engineering trying to delete code
	s, err := newAuthzABACCheckStep("check", map[string]any{
		"subject": "engineering",
		"object":  "code",
		"action":  "delete",
	})
	if err != nil {
		t.Fatalf("newAuthzABACCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != false {
		t.Errorf("expected allowed=false for engineering deleting code, got %v", result.Output["allowed"])
	}
}

func TestABAC_MultipleAttributeConditions(t *testing.T) {
	mod := abacTestModule(t, [][]string{
		{"engineering", "code", "read"},
		{"engineering", "code", "write"},
		{"engineering", "docs", "read"},
		{"marketing", "docs", "read"},
		{"marketing", "docs", "write"},
	})
	reg := &testRegistry{mod: mod}

	tests := []struct {
		name    string
		subject string
		object  string
		action  string
		want    bool
	}{
		{"eng can read code", "engineering", "code", "read", true},
		{"eng can write code", "engineering", "code", "write", true},
		{"eng can read docs", "engineering", "docs", "read", true},
		{"eng cannot write docs", "engineering", "docs", "write", false},
		{"mkt can read docs", "marketing", "docs", "read", true},
		{"mkt can write docs", "marketing", "docs", "write", true},
		{"mkt cannot read code", "marketing", "code", "read", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newAuthzABACCheckStep("check", map[string]any{
				"subject": tc.subject,
				"object":  tc.object,
				"action":  tc.action,
			})
			if err != nil {
				t.Fatalf("newAuthzABACCheckStep: %v", err)
			}
			s.registry = reg

			result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			got, _ := result.Output["allowed"].(bool)
			if got != tc.want {
				t.Errorf("expected allowed=%v, got %v", tc.want, got)
			}
		})
	}
}

func TestABAC_AddPolicy(t *testing.T) {
	mod := abacTestModule(t, nil)
	reg := &testRegistry{mod: mod}

	// Add a policy dynamically
	s, err := newAuthzABACAddPolicyStep("add", map[string]any{
		"rule": []any{"finance", "reports", "read"},
	})
	if err != nil {
		t.Fatalf("newAuthzABACAddPolicyStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["policy_added"] != true {
		t.Errorf("expected policy_added=true, got %v", result.Output["policy_added"])
	}

	// Check enforcement
	allowed, err := mod.Enforce("finance", "reports", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected finance to read reports after add_policy")
	}
}

func TestABAC_AddPolicy_MissingRule(t *testing.T) {
	_, err := newAuthzABACAddPolicyStep("bad", map[string]any{})
	if err == nil {
		t.Error("expected error for missing rule")
	}
}

func TestABAC_Check_MissingFields(t *testing.T) {
	for _, tc := range []map[string]any{
		{"subject": "a", "object": "b"},
		{"subject": "a", "action": "b"},
		{"object": "a", "action": "b"},
	} {
		_, err := newAuthzABACCheckStep("bad", tc)
		if err == nil {
			t.Errorf("expected error for config %v", tc)
		}
	}
}

func TestABAC_Check_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzABACCheckStep("no-mod", map[string]any{
		"subject": "a", "object": "b", "action": "c",
	})
	if err != nil {
		t.Fatalf("newAuthzABACCheckStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}
