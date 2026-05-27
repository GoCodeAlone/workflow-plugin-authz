package internal

import (
	"context"
	"os"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestKetoProviderWritesRoleScopeTuplesAndChecks(t *testing.T) {
	ctx := context.Background()
	client := &fakeKetoClient{checks: map[ketoTuple]bool{}}
	provider := newKetoScopeProvider("keto", client)

	scope := scopeDeclarationFromName("admin:authz.roles:update")
	if err := provider.DeclareScopes(ctx, []*contracts.ScopeDeclaration{scope}); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
	if err := provider.UpsertRole(ctx, RoleScopeGrant{
		Role:    "authz-admin",
		Context: "admin",
		Scopes:  []string{scope.GetName()},
	}); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	if !client.wrote(ketoTuple{
		Namespace: "scope",
		Object:    "admin:authz.roles:update",
		Relation:  "granted",
		SubjectSet: &ketoSubjectSet{
			Namespace: "role",
			Object:    "admin:authz-admin",
			Relation:  "member",
		},
	}) {
		t.Fatalf("missing role-scope tuple, wrote %#v", client.tuples)
	}

	if err := provider.AssignRole(ctx, SubjectRoleAssignment{Subject: "alice", Role: "authz-admin", Context: "admin"}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if !client.wrote(ketoTuple{Namespace: "role", Object: "admin:authz-admin", Relation: "member", SubjectID: "alice"}) {
		t.Fatalf("missing subject-role tuple, wrote %#v", client.tuples)
	}

	client.checks[ketoTuple{Namespace: "scope", Object: "admin:authz.roles:update", Relation: "granted", SubjectID: "alice"}] = true
	result, err := provider.CheckScope(ctx, ScopeCheck{Subject: "alice", Context: "admin", Scope: scope.GetName()})
	if err != nil {
		t.Fatalf("CheckScope: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected Keto check to allow, result=%#v", result)
	}
}

func TestKetoRealIntegration(t *testing.T) {
	if os.Getenv("KETO_INTEGRATION") != "1" {
		t.Skip("KETO_INTEGRATION=1 not set; skipping real Ory Keto SDK integration")
	}
	readURL := os.Getenv("KETO_READ_URL")
	writeURL := os.Getenv("KETO_WRITE_URL")
	if readURL == "" || writeURL == "" {
		t.Skip("missing KETO_READ_URL or KETO_WRITE_URL for real Ory Keto SDK integration")
	}
	provider := newKetoScopeProvider("keto", newKetoSDKClient(readURL, writeURL))
	ctx := context.Background()
	scope := scopeDeclarationFromName("admin:authz.roles:read")
	if err := provider.DeclareScopes(ctx, []*contracts.ScopeDeclaration{scope}); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
	if err := provider.UpsertRole(ctx, RoleScopeGrant{Role: "workflow-test-authz-viewer", Context: "admin", Scopes: []string{scope.GetName()}}); err != nil {
		t.Fatalf("UpsertRole through Keto SDK: %v", err)
	}
	if err := provider.AssignRole(ctx, SubjectRoleAssignment{Subject: "workflow-test-user", Role: "workflow-test-authz-viewer", Context: "admin"}); err != nil {
		t.Fatalf("AssignRole through Keto SDK: %v", err)
	}
}

type fakeKetoClient struct {
	tuples []ketoTuple
	checks map[ketoTuple]bool
}

func (f *fakeKetoClient) CreateRelationship(_ context.Context, tuple ketoTuple) error {
	f.tuples = append(f.tuples, tuple)
	return nil
}

func (f *fakeKetoClient) DeleteRelationship(_ context.Context, tuple ketoTuple) error {
	return nil
}

func (f *fakeKetoClient) Check(_ context.Context, tuple ketoTuple) (bool, error) {
	return f.checks[tuple], nil
}

func (f *fakeKetoClient) wrote(want ketoTuple) bool {
	for _, tuple := range f.tuples {
		if tuple.equal(want) {
			return true
		}
	}
	return false
}
