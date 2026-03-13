package internal

import (
	"context"
	"testing"
)

// rebacTestModule builds a Casbin module with a ReBAC model using g2 for
// relationship grouping.
func rebacTestModule(t *testing.T) *CasbinModule {
	t.Helper()

	m, err := newCasbinModule("authz", map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`,
		"policies": []any{
			[]any{"owner", "document", "read"},
			[]any{"owner", "document", "write"},
			[]any{"owner", "document", "delete"},
			[]any{"viewer", "document", "read"},
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return m
}

func TestReBAC_AddRelation(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzReBACAddRelationStep("add-rel", map[string]any{
		"subject":  "alice",
		"relation": "owner",
		"object":   "doc1",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACAddRelationStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["added"] != true {
		t.Errorf("expected added=true, got %v", result.Output["added"])
	}

	// Verify the relation was added by listing
	mod.mu.RLock()
	relations, _ := mod.enforcer.GetNamedGroupingPolicy("g2")
	mod.mu.RUnlock()

	found := false
	for _, r := range relations {
		if len(r) >= 3 && r[0] == "alice" && r[1] == "owner" && r[2] == "doc1" {
			found = true
		}
	}
	if !found {
		t.Error("expected relation (alice, owner, doc1) in g2 grouping policies")
	}
}

func TestReBAC_RemoveRelation(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	// First add a relation
	addStep, _ := newAuthzReBACAddRelationStep("add", map[string]any{
		"subject": "alice", "relation": "owner", "object": "doc1",
	})
	addStep.registry = reg
	_, err := addStep.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Now remove it
	s, err := newAuthzReBACRemoveRelationStep("remove-rel", map[string]any{
		"subject":  "alice",
		"relation": "owner",
		"object":   "doc1",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACRemoveRelationStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["removed"] != true {
		t.Errorf("expected removed=true, got %v", result.Output["removed"])
	}

	// Verify the relation was removed
	mod.mu.RLock()
	relations, _ := mod.enforcer.GetNamedGroupingPolicy("g2")
	mod.mu.RUnlock()

	for _, r := range relations {
		if len(r) >= 3 && r[0] == "alice" && r[1] == "owner" && r[2] == "doc1" {
			t.Error("relation should have been removed")
		}
	}
}

func TestReBAC_CheckPermission(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	// Assign alice the owner role (standard g grouping, not g2)
	_, err := mod.AddGroupingPolicy([]string{"alice", "owner"})
	if err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	s, err := newAuthzReBACCheckStep("check", map[string]any{
		"subject": "alice",
		"object":  "document",
		"action":  "write",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != true {
		t.Errorf("expected allowed=true for owner writing document, got %v", result.Output["allowed"])
	}
}

func TestReBAC_CheckPermission_Denied(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	// bob has viewer role
	_, err := mod.AddGroupingPolicy([]string{"bob", "viewer"})
	if err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	s, err := newAuthzReBACCheckStep("check", map[string]any{
		"subject": "bob",
		"object":  "document",
		"action":  "delete",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACCheckStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["allowed"] != false {
		t.Errorf("expected allowed=false for viewer deleting, got %v", result.Output["allowed"])
	}
}

func TestReBAC_RelationshipTraversal(t *testing.T) {
	// Model with relationship traversal: org -> team -> user
	m, err := newCasbinModule("authz", map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`,
		"policies": []any{
			[]any{"team_lead", "project", "manage"},
			[]any{"member", "project", "read"},
		},
		"roleAssignments": []any{
			[]any{"team_lead", "member"}, // team_lead inherits member
			[]any{"alice", "team_lead"},
			[]any{"bob", "member"},
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// alice (team_lead) should have both manage and read (inherited from member)
	allowed, _ := m.Enforce("alice", "project", "manage")
	if !allowed {
		t.Error("expected team_lead alice to manage project")
	}
	allowed, _ = m.Enforce("alice", "project", "read")
	if !allowed {
		t.Error("expected team_lead alice to read project (inherited from member)")
	}

	// bob (member) can read but not manage
	allowed, _ = m.Enforce("bob", "project", "read")
	if !allowed {
		t.Error("expected member bob to read project")
	}
	allowed, _ = m.Enforce("bob", "project", "manage")
	if allowed {
		t.Error("expected member bob to be denied manage")
	}
}

func TestReBAC_ListRelations_BySubject(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	// Add multiple relations
	for _, rel := range []struct{ sub, rel, obj string }{
		{"alice", "owner", "doc1"},
		{"alice", "editor", "doc2"},
		{"bob", "viewer", "doc1"},
	} {
		s, _ := newAuthzReBACAddRelationStep("add", map[string]any{
			"subject": rel.sub, "relation": rel.rel, "object": rel.obj,
		})
		s.registry = reg
		_, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("Add relation: %v", err)
		}
	}

	// List alice's relations
	s, err := newAuthzReBACListRelationsStep("list", map[string]any{
		"filter": "subject",
		"value":  "alice",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACListRelationsStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 2 {
		t.Errorf("expected 2 relations for alice, got %d", count)
	}
}

func TestReBAC_ListRelations_ByObject(t *testing.T) {
	mod := rebacTestModule(t)
	reg := &testRegistry{mod: mod}

	// Add relations
	for _, rel := range []struct{ sub, rel, obj string }{
		{"alice", "owner", "doc1"},
		{"bob", "viewer", "doc1"},
		{"carol", "editor", "doc2"},
	} {
		s, _ := newAuthzReBACAddRelationStep("add", map[string]any{
			"subject": rel.sub, "relation": rel.rel, "object": rel.obj,
		})
		s.registry = reg
		_, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("Add relation: %v", err)
		}
	}

	// List relations for doc1
	s, err := newAuthzReBACListRelationsStep("list", map[string]any{
		"filter": "object",
		"value":  "doc1",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACListRelationsStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 2 {
		t.Errorf("expected 2 relations for doc1, got %d", count)
	}
}

func TestReBAC_AddRelation_MissingFields(t *testing.T) {
	for _, tc := range []map[string]any{
		{"subject": "a", "relation": "b"},
		{"subject": "a", "object": "b"},
		{"relation": "a", "object": "b"},
	} {
		_, err := newAuthzReBACAddRelationStep("bad", tc)
		if err == nil {
			t.Errorf("expected error for config %v", tc)
		}
	}
}

func TestReBAC_AddRelation_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{}
	s, err := newAuthzReBACAddRelationStep("no-mod", map[string]any{
		"subject": "a", "relation": "b", "object": "c",
	})
	if err != nil {
		t.Fatalf("newAuthzReBACAddRelationStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

func TestReBAC_ListRelations_InvalidFilter(t *testing.T) {
	_, err := newAuthzReBACListRelationsStep("bad", map[string]any{
		"filter": "invalid",
		"value":  "test",
	})
	if err == nil {
		t.Error("expected error for invalid filter")
	}
}
