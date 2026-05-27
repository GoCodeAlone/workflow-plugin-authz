package internal

import (
	"context"
	"testing"
)

func TestReBACProviderCasbinConformance(t *testing.T) {
	ctx := context.Background()
	provider, ok := any(rebacTestModule(t)).(RelationshipProvider)
	if !ok {
		t.Fatal("CasbinModule should implement RelationshipProvider")
	}
	tuple := RelationTuple{Subject: "alice", Relation: "owner", Object: "doc1", Context: "frontend"}
	if err := provider.UpsertRelationTuple(ctx, tuple); err != nil {
		t.Fatalf("UpsertRelationTuple: %v", err)
	}
	result, err := provider.CheckRelation(ctx, RelationCheck{Subject: "alice", Relation: "owner", Object: "doc1", Context: "frontend"})
	if err != nil {
		t.Fatalf("CheckRelation: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected relation check to allow, got %#v", result)
	}
	listed, err := provider.ListRelationTuples(ctx, RelationTupleFilter{Subject: "alice", Context: "frontend"})
	if err != nil {
		t.Fatalf("ListRelationTuples: %v", err)
	}
	if len(listed) != 1 || listed[0].Object != "doc1" {
		t.Fatalf("listed tuples = %#v", listed)
	}
	if err := provider.RemoveRelationTuple(ctx, tuple); err != nil {
		t.Fatalf("RemoveRelationTuple: %v", err)
	}
	result, err = provider.CheckRelation(ctx, RelationCheck{Subject: "alice", Relation: "owner", Object: "doc1", Context: "frontend"})
	if err != nil {
		t.Fatalf("CheckRelation after remove: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected removed relation to stop allowing access")
	}
}

func TestReBACProviderKetoConformance(t *testing.T) {
	ctx := context.Background()
	client := &fakeKetoClient{checks: map[ketoTuple]bool{}}
	provider := newKetoScopeProvider("keto", client)
	tuple := RelationTuple{Subject: "alice", Relation: "viewer", Object: "doc1", Context: "frontend"}
	if err := provider.UpsertRelationTuple(ctx, tuple); err != nil {
		t.Fatalf("UpsertRelationTuple: %v", err)
	}
	want := ketoRelationshipTuple(tuple)
	if !client.wrote(want) {
		t.Fatalf("missing keto relation tuple, wrote %#v", client.tuples)
	}
	client.checks[want] = true
	result, err := provider.CheckRelation(ctx, RelationCheck{Subject: "alice", Relation: "viewer", Object: "doc1", Context: "frontend"})
	if err != nil {
		t.Fatalf("CheckRelation: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected Keto relation check to allow, got %#v", result)
	}
	listed, err := provider.ListRelationTuples(ctx, RelationTupleFilter{Object: "doc1", Context: "frontend"})
	if err != nil {
		t.Fatalf("ListRelationTuples: %v", err)
	}
	if len(listed) != 1 || listed[0].Subject != "alice" {
		t.Fatalf("listed tuples = %#v", listed)
	}
	if err := provider.RemoveRelationTuple(ctx, tuple); err != nil {
		t.Fatalf("RemoveRelationTuple: %v", err)
	}
	listed, _ = provider.ListRelationTuples(ctx, RelationTupleFilter{Object: "doc1", Context: "frontend"})
	if len(listed) != 0 {
		t.Fatalf("expected tuple removal to update local list, got %#v", listed)
	}
}

func TestReBACProviderFailsClosedForUnsupportedModels(t *testing.T) {
	provider, ok := any(aclTestModule(t, nil)).(RelationshipProvider)
	if !ok {
		t.Fatal("CasbinModule should expose unsupported ReBAC errors through RelationshipProvider")
	}
	err := provider.UpsertRelationTuple(context.Background(), RelationTuple{Subject: "alice", Relation: "owner", Object: "doc1", Context: "frontend"})
	if err == nil {
		t.Fatal("expected ACL model to reject ReBAC tuple writes")
	}
}
