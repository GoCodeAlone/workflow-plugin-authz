package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestCasbinScopeRoleProviderRejectsUnknownScopes(t *testing.T) {
	ctx := context.Background()
	provider := newTestCasbinScopeProvider(t)
	mustDeclareScopes(t, provider, "admin:authz.roles:read")

	err := provider.UpsertRole(ctx, RoleScopeGrant{
		Role:    "authz-admin",
		Context: "admin",
		Scopes:  []string{"admin:authz.roles:update"},
	})
	if err == nil {
		t.Fatal("expected unknown scope grant to fail")
	}
}

func TestCasbinScopeRoleProviderConformance(t *testing.T) {
	ctx := context.Background()
	provider := newTestCasbinScopeProvider(t)
	mustDeclareScopes(t, provider,
		"frontend:orders:read",
		"admin:dashboard:read",
		"admin:authz.roles:update",
	)

	if err := provider.UpsertRole(ctx, RoleScopeGrant{
		Role:    "requester",
		Context: "frontend",
		Scopes:  []string{"frontend:orders:read"},
	}); err != nil {
		t.Fatalf("UpsertRole requester: %v", err)
	}
	if err := provider.UpsertRole(ctx, RoleScopeGrant{
		Role:    "authz-admin",
		Context: "admin",
		Scopes:  []string{"admin:dashboard:read", "admin:authz.roles:update"},
	}); err != nil {
		t.Fatalf("UpsertRole authz-admin: %v", err)
	}
	if err := provider.AssignRole(ctx, SubjectRoleAssignment{
		Subject: "alice",
		Role:    "requester",
		Context: "frontend",
	}); err != nil {
		t.Fatalf("AssignRole frontend: %v", err)
	}
	if err := provider.AssignRole(ctx, SubjectRoleAssignment{
		Subject:      "alice",
		Role:         "temporary-admin",
		Context:      "admin",
		DirectScopes: []string{"admin:dashboard:read"},
	}); err != nil {
		t.Fatalf("AssignRole direct admin: %v", err)
	}

	assertScopeAllowed(t, provider, ScopeCheck{Subject: "alice", Context: "frontend", Scope: "frontend:orders:read"}, true)
	assertScopeAllowed(t, provider, ScopeCheck{Subject: "alice", Context: "frontend", Scope: "admin:dashboard:read"}, false)
	assertScopeAllowed(t, provider, ScopeCheck{Subject: "alice", Context: "admin", Scope: "admin:dashboard:read"}, true)
	assertScopeAllowed(t, provider, ScopeCheck{Subject: "alice", Context: "admin", Scope: "admin:authz.roles:update"}, false)

	assignments, err := provider.ListAssignments(ctx, AssignmentFilter{Subject: "alice"})
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(assignments) != 2 {
		t.Fatalf("assignments len = %d, want 2: %#v", len(assignments), assignments)
	}
}

func newTestCasbinScopeProvider(t *testing.T) ScopeRoleProvider {
	t.Helper()
	m := buildModule(t, nil, nil)
	provider, ok := any(m).(ScopeRoleProvider)
	if !ok {
		t.Fatalf("%T does not implement ScopeRoleProvider", m)
	}
	return provider
}

func mustDeclareScopes(t *testing.T, provider ScopeRoleProvider, names ...string) {
	t.Helper()
	scopes := make([]*contracts.ScopeDeclaration, 0, len(names))
	for _, name := range names {
		scope := scopeDeclarationFromName(name)
		scopes = append(scopes, scope)
	}
	if err := provider.DeclareScopes(context.Background(), scopes); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
}

func assertScopeAllowed(t *testing.T, provider ScopeRoleProvider, check ScopeCheck, want bool) {
	t.Helper()
	result, err := provider.CheckScope(context.Background(), check)
	if err != nil {
		t.Fatalf("CheckScope(%+v): %v", check, err)
	}
	if result.Allowed != want {
		t.Fatalf("CheckScope(%+v) allowed = %v, want %v; reason=%s", check, result.Allowed, want, result.Reason)
	}
}
