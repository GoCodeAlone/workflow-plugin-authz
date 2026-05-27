package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestABACProviderCasbinConformance(t *testing.T) {
	ctx := context.Background()
	provider, ok := any(abacAttributeTestModule(t)).(AttributePolicyProvider)
	if !ok {
		t.Fatal("CasbinModule should implement AttributePolicyProvider")
	}
	err := provider.DeclareAttributes(ctx, []*contracts.AttributeDeclaration{
		{Name: "department", Context: "frontend", Target: "subject", DataType: "string"},
		{Name: "kind", Context: "frontend", Target: "resource", DataType: "string"},
	})
	if err != nil {
		t.Fatalf("DeclareAttributes: %v", err)
	}
	policy := AttributePolicy{
		ID:       "support-code-read",
		Context:  "frontend",
		Resource: "document",
		Action:   "read",
		Effect:   "allow",
		Conditions: []AttributeCondition{
			{Target: "subject", Attribute: "department", Operator: "equals", Values: []string{"support"}},
			{Target: "resource", Attribute: "kind", Operator: "equals", Values: []string{"code"}},
		},
	}
	if err := provider.UpsertAttributePolicy(ctx, policy); err != nil {
		t.Fatalf("UpsertAttributePolicy: %v", err)
	}

	allowed, err := provider.CheckAttributes(ctx, AttributeCheck{
		Subject:            "alice",
		Context:            "frontend",
		Resource:           "document",
		Action:             "read",
		SubjectAttributes:  map[string]string{"department": "support"},
		ResourceAttributes: map[string]string{"kind": "code"},
	})
	if err != nil {
		t.Fatalf("CheckAttributes allowed: %v", err)
	}
	if !allowed.Allowed || allowed.MatchedPolicyID != "support-code-read" {
		t.Fatalf("allowed result = %#v", allowed)
	}

	denied, err := provider.CheckAttributes(ctx, AttributeCheck{
		Subject:            "bob",
		Context:            "frontend",
		Resource:           "document",
		Action:             "read",
		SubjectAttributes:  map[string]string{"department": "finance"},
		ResourceAttributes: map[string]string{"kind": "code"},
	})
	if err != nil {
		t.Fatalf("CheckAttributes denied: %v", err)
	}
	if denied.Allowed || denied.Reason == "" {
		t.Fatalf("denied result = %#v", denied)
	}

	policies, err := provider.ListAttributePolicies(ctx, AttributePolicyFilter{Context: "frontend"})
	if err != nil {
		t.Fatalf("ListAttributePolicies: %v", err)
	}
	if len(policies) != 1 || policies[0].ID != "support-code-read" {
		t.Fatalf("policies = %#v", policies)
	}
	if err := provider.RemoveAttributePolicy(ctx, AttributePolicyFilter{ID: "support-code-read", Context: "frontend"}); err != nil {
		t.Fatalf("RemoveAttributePolicy: %v", err)
	}
	afterRemove, err := provider.CheckAttributes(ctx, AttributeCheck{
		Subject:            "alice",
		Context:            "frontend",
		Resource:           "document",
		Action:             "read",
		SubjectAttributes:  map[string]string{"department": "support"},
		ResourceAttributes: map[string]string{"kind": "code"},
	})
	if err != nil {
		t.Fatalf("CheckAttributes after remove: %v", err)
	}
	if afterRemove.Allowed {
		t.Fatal("expected removed ABAC policy to stop allowing access")
	}
}

func TestABACProviderFailsClosedForMalformedAndUnsupported(t *testing.T) {
	ctx := context.Background()
	aclProvider, ok := any(aclTestModule(t, nil)).(AttributePolicyProvider)
	if !ok {
		t.Fatal("CasbinModule should expose unsupported ABAC errors through AttributePolicyProvider")
	}
	_, err := aclProvider.CheckAttributes(ctx, AttributeCheck{
		Subject:  "alice",
		Context:  "frontend",
		Resource: "document",
		Action:   "read",
	})
	if err == nil {
		t.Fatal("expected ACL Casbin model to reject ABAC checks")
	}

	permitProvider, ok := any(&PermitModule{name: "permit"}).(AttributePolicyProvider)
	if !ok {
		t.Fatal("PermitModule should implement AttributePolicyProvider with unsupported errors")
	}
	if err := permitProvider.UpsertAttributePolicy(ctx, AttributePolicy{ID: "p", Context: "frontend"}); err == nil {
		t.Fatal("expected Permit ABAC adapter to return unsupported until SDK surfaces are wired")
	}

	casbinProvider := any(abacAttributeTestModule(t)).(AttributePolicyProvider)
	err = casbinProvider.DeclareAttributes(ctx, []*contracts.AttributeDeclaration{
		{Name: "risk", Context: "frontend", Target: "subject", DataType: "currency"},
	})
	if err == nil {
		t.Fatal("expected invalid attribute declaration to fail closed")
	}
}
