package internal

import (
	"context"
	"os"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestPermitSDKProviderMapsScopeRolesAndChecks(t *testing.T) {
	ctx := context.Background()
	client := &fakePermitScopeClient{allowed: map[string]bool{}}
	provider := newPermitScopeProvider("permit", client)

	if err := provider.DeclareScopes(ctx, []*contracts.ScopeDeclaration{
		scopeDeclarationFromName("admin:authz.roles:update"),
	}); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
	if got := client.resources["authz.roles"]["update"]; !got {
		t.Fatalf("expected Permit resource/action authz.roles:update, got %#v", client.resources)
	}

	if err := provider.UpsertRole(ctx, RoleScopeGrant{
		Role:    "authz-admin",
		Context: "admin",
		Scopes:  []string{"admin:authz.roles:update"},
	}); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	if got := client.rolePermissions["admin__authz-admin"]["authz.roles:update"]; !got {
		t.Fatalf("expected Permit role permission, got %#v", client.rolePermissions)
	}

	if err := provider.AssignRole(ctx, SubjectRoleAssignment{
		Subject: "alice",
		Role:    "authz-admin",
		Context: "admin",
	}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if got := client.assignments["alice"]["admin__authz-admin"]; !got {
		t.Fatalf("expected Permit role assignment, got %#v", client.assignments)
	}

	client.allowed["alice|update|authz.roles"] = true
	result, err := provider.CheckScope(ctx, ScopeCheck{Subject: "alice", Context: "admin", Scope: "admin:authz.roles:update"})
	if err != nil {
		t.Fatalf("CheckScope: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected Permit check to allow, result=%#v", result)
	}
	if result.Provider != "permit" {
		t.Fatalf("provider = %q, want permit", result.Provider)
	}
}

func TestPermitRealIntegration(t *testing.T) {
	if os.Getenv("PERMIT_INTEGRATION") != "1" {
		t.Skip("PERMIT_INTEGRATION=1 not set; skipping real Permit.io SDK integration")
	}
	missing := []string{}
	for _, key := range []string{"PERMIT_API_KEY", "PERMIT_PROJECT", "PERMIT_ENVIRONMENT"} {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Skipf("missing Permit.io integration env vars: %v", missing)
	}
	provider := newPermitScopeProvider("permit", newPermitSDKScopeClient(permitModuleConfig{
		APIKey:      os.Getenv("PERMIT_API_KEY"),
		APIURL:      defaultString(os.Getenv("PERMIT_API_URL"), defaultPermitAPIURL),
		PDPURL:      defaultString(os.Getenv("PERMIT_PDP_URL"), defaultPermitPDPURL),
		Project:     os.Getenv("PERMIT_PROJECT"),
		Environment: os.Getenv("PERMIT_ENVIRONMENT"),
	}))
	ctx := context.Background()
	scope := scopeDeclarationFromName("admin:authz.roles:read")
	if err := provider.DeclareScopes(ctx, []*contracts.ScopeDeclaration{scope}); err != nil {
		t.Fatalf("DeclareScopes through Permit SDK: %v", err)
	}
	if err := provider.UpsertRole(ctx, RoleScopeGrant{Role: "workflow-test-authz-viewer", Context: "admin", Scopes: []string{scope.GetName()}}); err != nil {
		t.Fatalf("UpsertRole through Permit SDK: %v", err)
	}
}

type fakePermitScopeClient struct {
	resources       map[string]map[string]bool
	rolePermissions map[string]map[string]bool
	assignments     map[string]map[string]bool
	allowed         map[string]bool
}

func (f *fakePermitScopeClient) DeclareResource(_ context.Context, resource string, actions []string) error {
	if f.resources == nil {
		f.resources = map[string]map[string]bool{}
	}
	if f.resources[resource] == nil {
		f.resources[resource] = map[string]bool{}
	}
	for _, action := range actions {
		f.resources[resource][action] = true
	}
	return nil
}

func (f *fakePermitScopeClient) UpsertRole(_ context.Context, role string, permissions []string) error {
	if f.rolePermissions == nil {
		f.rolePermissions = map[string]map[string]bool{}
	}
	if f.rolePermissions[role] == nil {
		f.rolePermissions[role] = map[string]bool{}
	}
	for _, permission := range permissions {
		f.rolePermissions[role][permission] = true
	}
	return nil
}

func (f *fakePermitScopeClient) AssignRole(_ context.Context, subject, role, _ string) error {
	if f.assignments == nil {
		f.assignments = map[string]map[string]bool{}
	}
	if f.assignments[subject] == nil {
		f.assignments[subject] = map[string]bool{}
	}
	f.assignments[subject][role] = true
	return nil
}

func (f *fakePermitScopeClient) UnassignRole(_ context.Context, subject, role, _ string) error {
	if f.assignments != nil && f.assignments[subject] != nil {
		delete(f.assignments[subject], role)
	}
	return nil
}

func (f *fakePermitScopeClient) Check(_ context.Context, subject, action, resource string) (bool, error) {
	if f.allowed == nil {
		return false, nil
	}
	return f.allowed[subject+"|"+action+"|"+resource], nil
}
