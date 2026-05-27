package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestScopeCatalogModuleRegistersListsAndResolvesScopes(t *testing.T) {
	module := newScopeCatalogModule("catalog", map[string]any{
		"scopes": []any{
			map[string]any{
				"name":         "frontend:orders:read",
				"context":      "frontend",
				"resource":     "orders",
				"actions":      []any{"read"},
				"description":  "Read orders",
				"owner_plugin": "workflow-plugin-orders",
				"owner_module": "orders",
				"category":     "application",
			},
		},
	})

	registered, err := module.InvokeMethod("RegisterScopes", map[string]any{
		"owner_plugin": "workflow-plugin-admin",
		"owner_module": "admin",
		"scopes": []any{
			map[string]any{
				"name":        "admin:authz.roles:update",
				"context":     "admin",
				"resource":    "authz.roles",
				"actions":     []any{"update"},
				"description": "Manage role assignments",
				"category":    "security",
			},
		},
	})
	if err != nil {
		t.Fatalf("RegisterScopes: %v", err)
	}
	if registered["registered"] != 1 {
		t.Fatalf("registered = %v, want 1", registered["registered"])
	}

	listed, err := module.InvokeMethod("ListScopes", map[string]any{"context": "admin"})
	if err != nil {
		t.Fatalf("ListScopes: %v", err)
	}
	scopes := listed["scopes"].([]map[string]any)
	if len(scopes) != 1 || scopes[0]["owner_plugin"] != "workflow-plugin-admin" {
		t.Fatalf("admin scopes = %#v, want registered admin owner metadata", scopes)
	}

	resolved, err := module.InvokeMethod("ResolveSubjectScopes", map[string]any{
		"subject":       "admin@tailnet",
		"direct_scopes": []any{"frontend:orders:read"},
		"role_scopes":   []any{"admin:authz.roles:update"},
	})
	if err != nil {
		t.Fatalf("ResolveSubjectScopes: %v", err)
	}
	names := resolved["scopes"].([]string)
	if len(names) != 2 || names[0] != "admin:authz.roles:update" || names[1] != "frontend:orders:read" {
		t.Fatalf("resolved scopes = %#v, want sorted merged scopes", names)
	}
}

func TestScopeCatalogStrictContracts(t *testing.T) {
	provider := NewAuthzPlugin().(interface {
		sdk.TypedModuleProvider
		sdk.ContractProvider
	})

	config, err := anypb.New(&contracts.ScopeCatalogConfig{
		Scopes: []*contracts.ScopeDeclaration{
			{
				Name:        "admin:authz.scopes:read",
				Context:     "admin",
				Resource:    "authz.scopes",
				Actions:     []string{"read"},
				Description: "View declared scopes",
			},
		},
	})
	if err != nil {
		t.Fatalf("pack scope catalog config: %v", err)
	}
	if _, err := provider.CreateTypedModule("authz.scope_catalog", "catalog", config); err != nil {
		t.Fatalf("CreateTypedModule scope catalog: %v", err)
	}

	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, contract := range provider.ContractRegistry().Contracts {
		contractsByKey[contractKey(contract)] = contract
	}
	for _, key := range []string{
		"module:authz.scope_catalog",
		"service:ScopeCatalog/RegisterScopes",
		"service:ScopeCatalog/ListScopes",
		"service:ScopeCatalog/ResolveSubjectScopes",
		"service:ScopeCatalog/RegisterDeclarations",
		"service:ScopeCatalog/ListDeclarations",
		"service:ScopeCatalog/ResolveProjectionInputs",
	} {
		if contractsByKey[key] == nil {
			t.Fatalf("missing strict scope catalog contract %s", key)
		}
	}
}

func TestTypedScopeCatalogInputs(t *testing.T) {
	handler := typedRegisterScopes(newScopeCatalogModule("catalog", nil))
	result, err := handler(context.Background(), sdk.TypedStepRequest[*contracts.RegisterScopesInput, *contracts.RegisterScopesInput]{
		Config: &contracts.RegisterScopesInput{OwnerPlugin: "workflow-plugin-authz"},
		Input: &contracts.RegisterScopesInput{
			OwnerModule: "catalog",
			Scopes: []*contracts.ScopeDeclaration{
				{Name: "admin:authz.scopes:read", Context: "admin", Resource: "authz.scopes", Actions: []string{"read"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("typedRegisterScopes: %v", err)
	}
	if result.Output.GetRegistered() != 1 {
		t.Fatalf("registered = %d, want 1", result.Output.GetRegistered())
	}
}
