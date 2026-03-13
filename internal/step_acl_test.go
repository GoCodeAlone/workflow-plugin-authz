package internal

import (
	"context"
	"testing"
)

// aclTestModule builds a Casbin module with a simple ACL model (no roles).
func aclTestModule(t *testing.T, policies [][]string) *CasbinModule {
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

func TestACLGrant_GrantsAccess(t *testing.T) {
	mod := aclTestModule(t, nil)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzACLGrantStep("grant", map[string]any{
		"subject": "alice",
		"object":  "file1",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzACLGrantStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["granted"] != true {
		t.Errorf("expected granted=true, got %v", result.Output["granted"])
	}

	// Verify enforcement
	allowed, err := mod.Enforce("alice", "file1", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Error("expected alice to be allowed read file1 after grant")
	}
}

func TestACLCheck_Granted(t *testing.T) {
	mod := aclTestModule(t, [][]string{{"alice", "file1", "read"}})
	reg := &testRegistry{mod: mod}

	s, err := newAuthzACLCheckStep("check", map[string]any{
		"subject": "alice",
		"object":  "file1",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzACLCheckStep: %v", err)
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

func TestACLCheck_Denied(t *testing.T) {
	mod := aclTestModule(t, [][]string{{"alice", "file1", "read"}})
	reg := &testRegistry{mod: mod}

	s, err := newAuthzACLCheckStep("check", map[string]any{
		"subject": "bob",
		"object":  "file1",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzACLCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != false {
		t.Errorf("expected allowed=false, got %v", result.Output["allowed"])
	}
}

func TestACLRevoke_RevokesAccess(t *testing.T) {
	mod := aclTestModule(t, [][]string{{"alice", "file1", "read"}})
	reg := &testRegistry{mod: mod}

	// Verify alice has access first
	allowed, _ := mod.Enforce("alice", "file1", "read")
	if !allowed {
		t.Fatal("pre-condition: alice should have access")
	}

	s, err := newAuthzACLRevokeStep("revoke", map[string]any{
		"subject": "alice",
		"object":  "file1",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzACLRevokeStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["revoked"] != true {
		t.Errorf("expected revoked=true, got %v", result.Output["revoked"])
	}

	// Verify alice no longer has access
	allowed, _ = mod.Enforce("alice", "file1", "read")
	if allowed {
		t.Error("expected alice to be denied after revoke")
	}
}

func TestACLRevoke_ThenRecheck(t *testing.T) {
	mod := aclTestModule(t, [][]string{
		{"alice", "file1", "read"},
		{"alice", "file1", "write"},
	})
	reg := &testRegistry{mod: mod}

	// Revoke read only
	s, err := newAuthzACLRevokeStep("revoke-read", map[string]any{
		"subject": "alice",
		"object":  "file1",
		"action":  "read",
	})
	if err != nil {
		t.Fatalf("newAuthzACLRevokeStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// read should be denied, write should still be allowed
	readAllowed, _ := mod.Enforce("alice", "file1", "read")
	writeAllowed, _ := mod.Enforce("alice", "file1", "write")
	if readAllowed {
		t.Error("expected read to be denied after revoke")
	}
	if !writeAllowed {
		t.Error("expected write to still be allowed after revoking only read")
	}
}

func TestACLList_BySubject(t *testing.T) {
	mod := aclTestModule(t, [][]string{
		{"alice", "file1", "read"},
		{"alice", "file2", "write"},
		{"bob", "file1", "read"},
	})
	reg := &testRegistry{mod: mod}

	s, err := newAuthzACLListStep("list", map[string]any{
		"filter": "subject",
		"value":  "alice",
	})
	if err != nil {
		t.Fatalf("newAuthzACLListStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 2 {
		t.Errorf("expected 2 entries for alice, got %d", count)
	}
}

func TestACLList_ByObject(t *testing.T) {
	mod := aclTestModule(t, [][]string{
		{"alice", "file1", "read"},
		{"alice", "file2", "write"},
		{"bob", "file1", "read"},
	})
	reg := &testRegistry{mod: mod}

	s, err := newAuthzACLListStep("list", map[string]any{
		"filter": "object",
		"value":  "file1",
	})
	if err != nil {
		t.Fatalf("newAuthzACLListStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 2 {
		t.Errorf("expected 2 entries for file1, got %d", count)
	}
}

func TestACLGrant_MissingFields(t *testing.T) {
	for _, tc := range []map[string]any{
		{"subject": "a", "object": "b"}, // missing action
		{"subject": "a", "action": "b"}, // missing object
		{"object": "a", "action": "b"},  // missing subject
	} {
		_, err := newAuthzACLGrantStep("bad", tc)
		if err == nil {
			t.Errorf("expected error for config %v", tc)
		}
	}
}

func TestACLGrant_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzACLGrantStep("no-mod", map[string]any{
		"subject": "a", "object": "b", "action": "c",
	})
	if err != nil {
		t.Fatalf("newAuthzACLGrantStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

func TestACLList_InvalidFilter(t *testing.T) {
	_, err := newAuthzACLListStep("bad-filter", map[string]any{
		"filter": "invalid",
		"value":  "test",
	})
	if err == nil {
		t.Error("expected error for invalid filter")
	}
}
