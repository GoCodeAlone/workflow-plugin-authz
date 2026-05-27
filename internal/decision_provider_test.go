package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestAuthorizationDecisionRoutesRBACABACAndReBAC(t *testing.T) {
	ctx := context.Background()

	rbac := rbacTestModule(t, nil, nil)
	scope := &contracts.ScopeDeclaration{Name: "frontend:orders:read", Context: "frontend", Resource: "orders", Actions: []string{"read"}}
	if err := rbac.DeclareScopes(ctx, []*contracts.ScopeDeclaration{scope}); err != nil {
		t.Fatalf("DeclareScopes: %v", err)
	}
	if err := rbac.UpsertRole(ctx, RoleScopeGrant{Role: "reader", Context: "frontend", Scopes: []string{scope.GetName()}}); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	if err := rbac.AssignRole(ctx, SubjectRoleAssignment{Subject: "alice", Role: "reader", Context: "frontend"}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	rbacDecision, err := DecideAuthorization(ctx, rbac, AuthorizationDecisionInput{
		Mode:    CapabilityRBAC,
		Subject: "alice",
		Context: "frontend",
		Scope:   scope.GetName(),
	})
	if err != nil {
		t.Fatalf("RBAC decision: %v", err)
	}
	if !rbacDecision.Allowed || rbacDecision.Mode != CapabilityRBAC {
		t.Fatalf("RBAC decision = %#v", rbacDecision)
	}

	abac := abacAttributeTestModule(t)
	if err := abac.DeclareAttributes(ctx, []*contracts.AttributeDeclaration{{Name: "department", Context: "frontend", Target: "subject", DataType: "string"}}); err != nil {
		t.Fatalf("DeclareAttributes: %v", err)
	}
	if err := abac.UpsertAttributePolicy(ctx, AttributePolicy{ID: "support-read", Context: "frontend", Resource: "ticket", Action: "read", Conditions: []AttributeCondition{{Target: "subject", Attribute: "department", Values: []string{"support"}}}}); err != nil {
		t.Fatalf("UpsertAttributePolicy: %v", err)
	}
	abacDecision, err := DecideAuthorization(ctx, abac, AuthorizationDecisionInput{
		Mode:              CapabilityABAC,
		Subject:           "bob",
		Context:           "frontend",
		Resource:          "ticket",
		Action:            "read",
		SubjectAttributes: map[string]string{"department": "support"},
	})
	if err != nil {
		t.Fatalf("ABAC decision: %v", err)
	}
	if !abacDecision.Allowed || abacDecision.Mode != CapabilityABAC {
		t.Fatalf("ABAC decision = %#v", abacDecision)
	}

	rebac := rebacTestModule(t)
	if err := rebac.UpsertRelationTuple(ctx, RelationTuple{Subject: "carol", Relation: "owner", Object: "doc1", Context: "frontend"}); err != nil {
		t.Fatalf("UpsertRelationTuple: %v", err)
	}
	rebacDecision, err := DecideAuthorization(ctx, rebac, AuthorizationDecisionInput{
		Mode:     CapabilityReBAC,
		Subject:  "carol",
		Context:  "frontend",
		Resource: "doc1",
		Relation: "owner",
	})
	if err != nil {
		t.Fatalf("ReBAC decision: %v", err)
	}
	if !rebacDecision.Allowed || rebacDecision.Mode != CapabilityReBAC {
		t.Fatalf("ReBAC decision = %#v", rebacDecision)
	}
}

func TestAuthorizationDecisionRejectsAmbiguousOrUnsupportedMode(t *testing.T) {
	_, err := DecideAuthorization(context.Background(), aclTestModule(t, nil), AuthorizationDecisionInput{
		Subject: "alice",
		Context: "frontend",
	})
	if err == nil {
		t.Fatal("expected ambiguous decision request to fail")
	}

	_, err = DecideAuthorization(context.Background(), aclTestModule(t, nil), AuthorizationDecisionInput{
		Mode:    CapabilityABAC,
		Subject: "alice",
		Context: "frontend",
	})
	if err == nil {
		t.Fatal("expected unsupported ABAC decision to fail")
	}
}
