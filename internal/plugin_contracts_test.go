package internal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestPluginImplementsStrictContractProviders(t *testing.T) {
	provider := NewAuthzPlugin()
	if _, ok := provider.(sdk.TypedModuleProvider); !ok {
		t.Fatal("expected TypedModuleProvider")
	}
	if _, ok := provider.(sdk.TypedStepProvider); !ok {
		t.Fatal("expected TypedStepProvider")
	}
	if _, ok := provider.(sdk.ContractProvider); !ok {
		t.Fatal("expected ContractProvider")
	}
}

func TestContractRegistryDeclaresStrictContracts(t *testing.T) {
	provider := NewAuthzPlugin().(sdk.ContractProvider)
	registry := provider.ContractRegistry()
	if registry == nil {
		t.Fatal("expected contract registry")
	}
	if registry.FileDescriptorSet == nil || len(registry.FileDescriptorSet.File) == 0 {
		t.Fatal("expected file descriptor set")
	}
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("descriptor set: %v", err)
	}

	manifestContracts := loadManifestContracts(t)
	contractsByKey := make(map[string]*pb.ContractDescriptor, len(registry.Contracts))
	for _, contract := range registry.Contracts {
		if contract.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("%s mode = %s, want strict proto", contractKey(contract), contract.Mode)
		}
		key := contractKey(contract)
		if _, exists := contractsByKey[key]; exists {
			t.Fatalf("duplicate runtime contract %q", key)
		}
		contractsByKey[key] = contract
		for _, name := range []string{contract.ConfigMessage, contract.InputMessage, contract.OutputMessage} {
			if name == "" {
				continue
			}
			if _, err := files.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
				t.Fatalf("%s references unknown message %s: %v", key, name, err)
			}
		}
		want, ok := manifestContracts[key]
		if !ok {
			t.Fatalf("%s missing from plugin.contracts.json", key)
		}
		if want.ConfigMessage != contract.ConfigMessage || want.InputMessage != contract.InputMessage || want.OutputMessage != contract.OutputMessage {
			t.Fatalf("%s manifest contract = %#v, runtime = %#v", key, want, contract)
		}
	}
	if len(contractsByKey) != len(manifestContracts) {
		t.Fatalf("runtime contract count = %d, manifest = %d", len(contractsByKey), len(manifestContracts))
	}
}

func TestProviderCapabilitiesStrictProtoTypes(t *testing.T) {
	req := &contracts.ProviderCapabilitiesInput{
		Module:   "authz",
		Provider: "casbin",
		Requirements: []*contracts.CapabilityRequirement{{
			Mode:       contracts.AuthzMode_AUTHZ_MODE_RBAC,
			Operations: []contracts.AuthzOperation{contracts.AuthzOperation_AUTHZ_OPERATION_CHECK},
		}},
	}
	out := &contracts.ProviderCapabilitiesOutput{
		Module:       req.GetModule(),
		Provider:     req.GetProvider(),
		Capabilities: []string{"rbac"},
		Descriptors: []*contracts.CapabilityDescriptor{{
			Mode:       contracts.AuthzMode_AUTHZ_MODE_RBAC,
			Operations: []contracts.AuthzOperation{contracts.AuthzOperation_AUTHZ_OPERATION_CHECK},
			Configured: true,
			Source:     "detected",
			Health:     "ok",
		}},
	}
	if out.GetDescriptors()[0].GetMode() != req.GetRequirements()[0].GetMode() {
		t.Fatal("capability descriptor mode should use strict proto enums")
	}
}

func TestContractRegistryDeclaresProviderCapabilitiesService(t *testing.T) {
	provider := NewAuthzPlugin().(sdk.ContractProvider)
	registry := provider.ContractRegistry()
	var getFound, requireFound bool
	for _, contract := range registry.Contracts {
		if contract.Kind != pb.ContractKind_CONTRACT_KIND_SERVICE || contract.ServiceName != "ProviderCapabilities" {
			continue
		}
		switch contract.Method {
		case "GetCapabilities":
			getFound = contract.InputMessage == "workflow.plugins.authz.v1.ProviderCapabilitiesInput" &&
				contract.OutputMessage == "workflow.plugins.authz.v1.ProviderCapabilitiesOutput"
		case "RequireCapabilities":
			requireFound = contract.InputMessage == "workflow.plugins.authz.v1.ProviderCapabilitiesInput" &&
				contract.OutputMessage == "workflow.plugins.authz.v1.ProviderCapabilitiesOutput"
		}
	}
	if !getFound {
		t.Fatal("missing ProviderCapabilities/GetCapabilities strict service contract")
	}
	if !requireFound {
		t.Fatal("missing ProviderCapabilities/RequireCapabilities strict service contract")
	}
}

func TestTypeListsAreDefensiveCopies(t *testing.T) {
	provider := NewAuthzPlugin()
	moduleProvider := provider.(sdk.ModuleProvider)
	typedModuleProvider := provider.(sdk.TypedModuleProvider)
	stepProvider := provider.(sdk.StepProvider)
	typedStepProvider := provider.(sdk.TypedStepProvider)

	moduleTypes := moduleProvider.ModuleTypes()
	moduleTypes[0] = "mutated"
	if got := moduleProvider.ModuleTypes()[0]; got == "mutated" {
		t.Fatal("ModuleTypes exposed mutable package-level slice")
	}

	typedModuleTypes := typedModuleProvider.TypedModuleTypes()
	typedModuleTypes[0] = "mutated"
	if got := typedModuleProvider.TypedModuleTypes()[0]; got == "mutated" {
		t.Fatal("TypedModuleTypes exposed mutable package-level slice")
	}

	stepTypes := stepProvider.StepTypes()
	stepTypes[0] = "mutated"
	if got := stepProvider.StepTypes()[0]; got == "mutated" {
		t.Fatal("StepTypes exposed mutable package-level slice")
	}

	typedStepTypes := typedStepProvider.TypedStepTypes()
	typedStepTypes[0] = "mutated"
	if got := typedStepProvider.TypedStepTypes()[0]; got == "mutated" {
		t.Fatal("TypedStepTypes exposed mutable package-level slice")
	}
}

func TestTypedProvidersValidateConfig(t *testing.T) {
	provider := NewAuthzPlugin().(interface {
		sdk.TypedModuleProvider
		sdk.TypedStepProvider
	})

	moduleConfig, err := anypb.New(&contracts.CasbinModuleConfig{Model: testModel})
	if err != nil {
		t.Fatalf("pack module config: %v", err)
	}
	if _, err := provider.CreateTypedModule("authz.casbin", "authz", moduleConfig); err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}

	stepConfig, err := anypb.New(&contracts.AuthzCheckConfig{Object: "/docs", Action: "read"})
	if err != nil {
		t.Fatalf("pack step config: %v", err)
	}
	if _, err := provider.CreateTypedModule("authz.casbin", "authz", stepConfig); err == nil {
		t.Fatal("CreateTypedModule accepted wrong typed config")
	}
	if _, err := provider.CreateTypedStep("step.authz_check_casbin", "check", stepConfig); err != nil {
		t.Fatalf("CreateTypedStep: %v", err)
	}
	if _, err := provider.CreateTypedStep("step.authz_check_casbin", "check", moduleConfig); err == nil {
		t.Fatal("CreateTypedStep accepted wrong typed config")
	}
}

func TestTypedAddPolicyInputOverridesStaticConfigAndStaysInModuleBoundary(t *testing.T) {
	mod := buildModule(t, nil, nil)
	reg := &testRegistry{mod: mod}

	result, err := typedAuthzAddPolicy(reg)(context.Background(), sdk.TypedStepRequest[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput]{
		Config: &contracts.PolicyRuleConfig{
			Module: "authz",
			Rule:   []string{"static-role", "/static", "read"},
		},
		Input: &contracts.PolicyRuleInput{
			Rule: []string{"runtime-role", "/runtime", "write"},
		},
	})
	if err != nil {
		t.Fatalf("typedAuthzAddPolicy: %v", err)
	}
	if result == nil || result.Output == nil {
		t.Fatal("expected typed output")
	}
	if !result.Output.GetChanged() {
		t.Fatal("expected policy to be added")
	}

	allowed, err := mod.Enforce("runtime-role", "/runtime", "write")
	if err != nil {
		t.Fatalf("runtime Enforce: %v", err)
	}
	if !allowed {
		t.Fatal("expected runtime input policy to be added")
	}
	allowed, err = mod.Enforce("static-role", "/static", "read")
	if err != nil {
		t.Fatalf("static Enforce: %v", err)
	}
	if allowed {
		t.Fatal("static config policy should not be added when typed input supplies a rule")
	}
}

type manifestContract struct {
	Mode          string `json:"mode"`
	ConfigMessage string `json:"config"`
	InputMessage  string `json:"input"`
	OutputMessage string `json:"output"`
}

func loadManifestContracts(t *testing.T) map[string]manifestContract {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var manifest struct {
		Version   string `json:"version"`
		Contracts []struct {
			Kind        string `json:"kind"`
			Type        string `json:"type"`
			ServiceName string `json:"serviceName"`
			Method      string `json:"method"`
			manifestContract
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if manifest.Version != "v1" {
		t.Fatalf("plugin.contracts.json version = %q, want v1", manifest.Version)
	}
	out := make(map[string]manifestContract, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		if contract.Mode != "strict" {
			t.Fatalf("%s mode = %q, want strict", contract.Type, contract.Mode)
		}
		var key string
		switch contract.Kind {
		case "module":
			key = "module:" + contract.Type
		case "step":
			key = "step:" + contract.Type
		case "service_method":
			key = "service:" + contract.ServiceName + "/" + contract.Method
		default:
			t.Fatalf("unexpected contract kind %q in plugin.contracts.json", contract.Kind)
		}
		if _, exists := out[key]; exists {
			t.Fatalf("duplicate contract %q in plugin.contracts.json", key)
		}
		out[key] = contract.manifestContract
	}
	return out
}

func contractKey(contract *pb.ContractDescriptor) string {
	switch contract.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + contract.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + contract.StepType
	case pb.ContractKind_CONTRACT_KIND_SERVICE:
		return "service:" + contract.ServiceName + "/" + contract.Method
	default:
		return contract.Kind.String()
	}
}
