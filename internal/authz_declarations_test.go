package internal

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

func TestAuthzDeclarationsRegisterListAndProjection(t *testing.T) {
	module := newScopeCatalogModule("catalog", nil)
	out, err := module.InvokeMethod("RegisterDeclarations", map[string]any{
		"owner_plugin": "workflow-plugin-orders",
		"owner_module": "orders",
		"declarations": map[string]any{
			"resources": []any{
				map[string]any{
					"name":             "orders.order",
					"context":          "frontend",
					"display_name":     "Order",
					"description":      "Customer order",
					"lookup_source_id": "orders",
				},
			},
			"actions": []any{
				map[string]any{"name": "read", "context": "frontend", "resource": "orders.order"},
				map[string]any{"name": "refund", "context": "frontend", "resource": "orders.order"},
			},
			"scopes": []any{
				map[string]any{
					"name":     "frontend:orders.order:read",
					"context":  "frontend",
					"resource": "orders.order",
					"actions":  []any{"read"},
				},
			},
			"attributes": []any{
				map[string]any{
					"name":             "subject.department",
					"context":          "frontend",
					"target":           "subject",
					"data_type":        "string",
					"lookup_source_id": "departments",
					"allowed_values": []any{
						map[string]any{"value": "support", "label": "Support"},
						map[string]any{"value": "finance", "label": "Finance"},
					},
				},
			},
			"relations": []any{
				map[string]any{
					"name":         "owner",
					"context":      "frontend",
					"subject_type": "user",
					"object_type":  "orders.order",
				},
			},
			"ui_actions": []any{
				map[string]any{
					"id":              "orders.refund",
					"context":         "frontend",
					"label":           "Refund order",
					"route":           "/orders/:id",
					"required_scopes": []any{"frontend:orders.order:refund"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("RegisterDeclarations: %v", err)
	}
	if out["registered"] != 7 {
		t.Fatalf("registered = %v, want 7 declarations", out["registered"])
	}

	listed, err := module.InvokeMethod("ListDeclarations", map[string]any{"context": "frontend"})
	if err != nil {
		t.Fatalf("ListDeclarations: %v", err)
	}
	declarations := listed["declarations"].(map[string]any)
	resources := declarations["resources"].([]map[string]any)
	if len(resources) != 1 || resources[0]["owner_plugin"] != "workflow-plugin-orders" {
		t.Fatalf("resources = %#v, want owner metadata", resources)
	}
	attributes := declarations["attributes"].([]map[string]any)
	if attributes[0]["lookup_source_id"] != "departments" {
		t.Fatalf("attribute lookup source = %#v, want departments", attributes[0])
	}

	projected, err := module.InvokeMethod("ResolveProjectionInputs", map[string]any{"context": "frontend"})
	if err != nil {
		t.Fatalf("ResolveProjectionInputs: %v", err)
	}
	projection := projected["projection"].(map[string]any)
	if got := projection["scope_names"].([]string); len(got) != 1 || got[0] != "frontend:orders.order:read" {
		t.Fatalf("scope_names = %#v", got)
	}
	if got := projection["lookup_source_ids"].([]string); len(got) != 2 || got[0] != "departments" || got[1] != "orders" {
		t.Fatalf("lookup_source_ids = %#v, want sorted unique lookup IDs", got)
	}
}

func TestAuthzDeclarationsRejectInvalidDeclarations(t *testing.T) {
	module := newScopeCatalogModule("catalog", nil)
	_, err := module.InvokeMethod("RegisterDeclarations", map[string]any{
		"declarations": map[string]any{
			"attributes": []any{
				map[string]any{
					"name":      "subject.risk",
					"context":   "admin",
					"target":    "subject",
					"data_type": "currency",
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid attribute data type to fail")
	}
}

func TestAuthzDeclarationsAreProviderNeutral(t *testing.T) {
	set := &contracts.AuthzDeclarationSet{
		OwnerPlugin: "workflow-plugin-docs",
		OwnerModule: "docs",
		Resources: []*contracts.ResourceDeclaration{{
			Name:    "docs.document",
			Context: "frontend",
		}},
		Actions: []*contracts.ActionDeclaration{{
			Name:     "read",
			Context:  "frontend",
			Resource: "docs.document",
		}},
		Relations: []*contracts.RelationDeclaration{{
			Name:        "viewer",
			Context:     "frontend",
			SubjectType: "user",
			ObjectType:  "docs.document",
		}},
	}
	module := newScopeCatalogModule("catalog", nil)
	out, err := module.registerDeclarations(&contracts.RegisterDeclarationsInput{Declarations: set})
	if err != nil {
		t.Fatalf("registerDeclarations: %v", err)
	}
	if out.GetRegistered() != 3 {
		t.Fatalf("registered = %d, want 3", out.GetRegistered())
	}
	listed := module.listDeclarations(&contracts.ListDeclarationsInput{Context: "frontend"})
	if len(listed.GetResources()) != 1 || listed.GetResources()[0].GetOwnerPlugin() != "workflow-plugin-docs" {
		t.Fatalf("listed resources = %#v", listed.GetResources())
	}
}
