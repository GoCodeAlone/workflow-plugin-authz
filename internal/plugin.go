// Package internal implements the workflow-plugin-authz plugin, providing
// Casbin-based RBAC authorization and Permit.io authorization as modules and pipeline steps.
package internal

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-authz/internal.Version=X.Y.Z"
var Version = "0.0.0"

// authzPlugin implements sdk.PluginProvider, sdk.ModuleProvider, and sdk.StepProvider.
type authzPlugin struct{}

var moduleTypes = []string{"authz.casbin", "permit.provider"}

var casbinStepTypes = []string{
	"step.authz_check_casbin",
	"step.authz_add_policy",
	"step.authz_remove_policy",
	"step.authz_role_assign",
	"step.authz_capabilities",
	"step.authz_acl_grant",
	"step.authz_acl_revoke",
	"step.authz_acl_check",
	"step.authz_acl_list",
	"step.authz_abac_check",
	"step.authz_abac_add_policy",
	"step.authz_rebac_add_relation",
	"step.authz_rebac_remove_relation",
	"step.authz_rebac_check",
	"step.authz_rebac_list_relations",
}

// NewAuthzPlugin returns a new authzPlugin instance.
func NewAuthzPlugin() sdk.PluginProvider {
	return &authzPlugin{}
}

// Manifest returns plugin metadata.
func (p *authzPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-authz",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "RBAC authorization plugin using Casbin and Permit.io",
	}
}

// ModuleTypes returns the module type names this plugin provides.
func (p *authzPlugin) ModuleTypes() []string {
	return append([]string(nil), moduleTypes...)
}

// TypedModuleTypes returns the module type names this plugin provides as strict protobuf contracts.
func (p *authzPlugin) TypedModuleTypes() []string {
	return append([]string(nil), moduleTypes...)
}

// CreateModule creates a module instance of the given type and registers it
// in the global registry so that steps can locate it by name.
func (p *authzPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "authz.casbin":
		m, err := newCasbinModule(name, config)
		if err != nil {
			return nil, err
		}
		RegisterModule(m)
		return m, nil
	case "permit.provider":
		m, err := newPermitModule(name, config)
		if err != nil {
			return nil, err
		}
		return m, nil
	default:
		return nil, fmt.Errorf("authz plugin: unknown module type %q", typeName)
	}
}

// CreateTypedModule creates a protobuf-backed module instance.
func (p *authzPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "authz.casbin":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.CasbinModuleConfig{}, func(name string, cfg *contracts.CasbinModuleConfig) (sdk.ModuleInstance, error) {
			m, err := newCasbinModule(name, casbinModuleConfigToMap(cfg))
			if err != nil {
				return nil, err
			}
			RegisterModule(m)
			return m, nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "permit.provider":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.PermitModuleConfig{}, func(name string, cfg *contracts.PermitModuleConfig) (sdk.ModuleInstance, error) {
			return newPermitModule(name, permitModuleConfigToMap(cfg))
		})
		return factory.CreateTypedModule(typeName, name, config)
	default:
		return nil, fmt.Errorf("authz plugin: unknown module type %q", typeName)
	}
}

// StepTypes returns the step type names this plugin provides.
func (p *authzPlugin) StepTypes() []string {
	stepTypes := append([]string(nil), casbinStepTypes...)
	return append(stepTypes, permitStepTypes()...)
}

// TypedStepTypes returns the step type names this plugin provides as strict protobuf contracts.
func (p *authzPlugin) TypedStepTypes() []string {
	return p.StepTypes()
}

// CreateStep creates a step instance of the given type.
func (p *authzPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.authz_check_casbin":
		return newAuthzCheckStep(name, config)
	case "step.authz_add_policy":
		return newAuthzAddPolicyStep(name, config)
	case "step.authz_remove_policy":
		return newAuthzRemovePolicyStep(name, config)
	case "step.authz_role_assign":
		return newAuthzRoleAssignStep(name, config)
	case "step.authz_capabilities":
		return newAuthzCapabilitiesStep(name, config)
	// ACL steps
	case "step.authz_acl_grant":
		return newAuthzACLGrantStep(name, config)
	case "step.authz_acl_revoke":
		return newAuthzACLRevokeStep(name, config)
	case "step.authz_acl_check":
		return newAuthzACLCheckStep(name, config)
	case "step.authz_acl_list":
		return newAuthzACLListStep(name, config)
	// ABAC steps
	case "step.authz_abac_check":
		return newAuthzABACCheckStep(name, config)
	case "step.authz_abac_add_policy":
		return newAuthzABACAddPolicyStep(name, config)
	// ReBAC steps
	case "step.authz_rebac_add_relation":
		return newAuthzReBACAddRelationStep(name, config)
	case "step.authz_rebac_remove_relation":
		return newAuthzReBACRemoveRelationStep(name, config)
	case "step.authz_rebac_check":
		return newAuthzReBACCheckStep(name, config)
	case "step.authz_rebac_list_relations":
		return newAuthzReBACListRelationsStep(name, config)
	default:
		// Delegate to permit step registry for all step.permit_* types.
		if step, err := createPermitStep(typeName, name, config); err == nil {
			return step, nil
		}
		return nil, fmt.Errorf("authz plugin: unknown step type %q", typeName)
	}
}

// CreateTypedStep creates a protobuf-backed step instance.
func (p *authzPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.authz_check_casbin":
		return sdk.NewTypedStepFactory(typeName, &contracts.AuthzCheckConfig{}, &contracts.AuthzCheckInput{}, typedAuthzCheck(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_add_policy":
		return sdk.NewTypedStepFactory(typeName, &contracts.PolicyRuleConfig{}, &contracts.PolicyRuleInput{}, typedAuthzAddPolicy(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_remove_policy":
		return sdk.NewTypedStepFactory(typeName, &contracts.PolicyRuleConfig{}, &contracts.PolicyRuleInput{}, typedAuthzRemovePolicy(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_role_assign":
		return sdk.NewTypedStepFactory(typeName, &contracts.RoleAssignConfig{}, &contracts.RoleAssignInput{}, typedAuthzRoleAssign(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_capabilities":
		return sdk.NewTypedStepFactory(typeName, &contracts.CapabilitiesConfig{}, &contracts.CapabilitiesInput{}, typedAuthzCapabilities(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_acl_grant":
		return sdk.NewTypedStepFactory(typeName, &contracts.SubjectObjectActionConfig{}, &contracts.SubjectObjectActionInput{}, typedSubjectObjectAction(wrapStepConstructor(newAuthzACLGrantStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_acl_revoke":
		return sdk.NewTypedStepFactory(typeName, &contracts.SubjectObjectActionConfig{}, &contracts.SubjectObjectActionInput{}, typedSubjectObjectAction(wrapStepConstructor(newAuthzACLRevokeStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_acl_check":
		return sdk.NewTypedStepFactory(typeName, &contracts.SubjectObjectActionConfig{}, &contracts.SubjectObjectActionInput{}, typedSubjectObjectAction(wrapStepConstructor(newAuthzACLCheckStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_acl_list":
		return sdk.NewTypedStepFactory(typeName, &contracts.ListConfig{}, &contracts.ListInput{}, typedList(wrapStepConstructor(newAuthzACLListStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_abac_check":
		return sdk.NewTypedStepFactory(typeName, &contracts.SubjectObjectActionConfig{}, &contracts.SubjectObjectActionInput{}, typedSubjectObjectAction(wrapStepConstructor(newAuthzABACCheckStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_abac_add_policy":
		return sdk.NewTypedStepFactory(typeName, &contracts.PolicyRuleConfig{}, &contracts.PolicyRuleInput{}, typedAuthzABACAddPolicy(globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_rebac_add_relation":
		return sdk.NewTypedStepFactory(typeName, &contracts.RelationConfig{}, &contracts.RelationInput{}, typedRelation(wrapStepConstructor(newAuthzReBACAddRelationStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_rebac_remove_relation":
		return sdk.NewTypedStepFactory(typeName, &contracts.RelationConfig{}, &contracts.RelationInput{}, typedRelation(wrapStepConstructor(newAuthzReBACRemoveRelationStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_rebac_check":
		return sdk.NewTypedStepFactory(typeName, &contracts.SubjectObjectActionConfig{}, &contracts.SubjectObjectActionInput{}, typedSubjectObjectAction(wrapStepConstructor(newAuthzReBACCheckStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	case "step.authz_rebac_list_relations":
		return sdk.NewTypedStepFactory(typeName, &contracts.ListConfig{}, &contracts.ListInput{}, typedList(wrapStepConstructor(newAuthzReBACListRelationsStep), globalRegistry)).CreateTypedStep(typeName, name, config)
	default:
		if isPermitStepType(typeName) {
			return sdk.NewTypedStepFactory(typeName, &contracts.PermitStepConfig{}, &contracts.PermitStepInput{}, typedPermitStep(typeName)).CreateTypedStep(typeName, name, config)
		}
		return nil, fmt.Errorf("authz plugin: unknown step type %q", typeName)
	}
}

// ContractRegistry returns the protobuf descriptors and strict contract declarations.
func (p *authzPlugin) ContractRegistry() *pb.ContractRegistry {
	contractsList := []*pb.ContractDescriptor{
		moduleContract("authz.casbin", "CasbinModuleConfig"),
		moduleContract("permit.provider", "PermitModuleConfig"),
		stepContract("step.authz_check_casbin", "AuthzCheckConfig", "AuthzCheckInput", "AuthzCheckOutput"),
		stepContract("step.authz_add_policy", "PolicyRuleConfig", "PolicyRuleInput", "PolicyRuleOutput"),
		stepContract("step.authz_remove_policy", "PolicyRuleConfig", "PolicyRuleInput", "PolicyRuleOutput"),
		stepContract("step.authz_role_assign", "RoleAssignConfig", "RoleAssignInput", "RoleAssignOutput"),
		stepContract("step.authz_capabilities", "CapabilitiesConfig", "CapabilitiesInput", "CapabilitiesOutput"),
		stepContract("step.authz_acl_grant", "SubjectObjectActionConfig", "SubjectObjectActionInput", "SubjectObjectActionOutput"),
		stepContract("step.authz_acl_revoke", "SubjectObjectActionConfig", "SubjectObjectActionInput", "SubjectObjectActionOutput"),
		stepContract("step.authz_acl_check", "SubjectObjectActionConfig", "SubjectObjectActionInput", "SubjectObjectActionOutput"),
		stepContract("step.authz_acl_list", "ListConfig", "ListInput", "GenericStepOutput"),
		stepContract("step.authz_abac_check", "SubjectObjectActionConfig", "SubjectObjectActionInput", "SubjectObjectActionOutput"),
		stepContract("step.authz_abac_add_policy", "PolicyRuleConfig", "PolicyRuleInput", "PolicyRuleOutput"),
		stepContract("step.authz_rebac_add_relation", "RelationConfig", "RelationInput", "RelationOutput"),
		stepContract("step.authz_rebac_remove_relation", "RelationConfig", "RelationInput", "RelationOutput"),
		stepContract("step.authz_rebac_check", "SubjectObjectActionConfig", "SubjectObjectActionInput", "SubjectObjectActionOutput"),
		stepContract("step.authz_rebac_list_relations", "ListConfig", "ListInput", "GenericStepOutput"),
	}
	for _, stepType := range permitStepTypes() {
		contractsList = append(contractsList, stepContract(stepType, "PermitStepConfig", "PermitStepInput", "GenericStepOutput"))
	}
	return &pb.ContractRegistry{
		FileDescriptorSet: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(structpb.File_google_protobuf_struct_proto),
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_authz_proto),
		}},
		Contracts: contractsList,
	}
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.authz.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.authz.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func wrapStepConstructor[T sdk.StepInstance](ctor func(string, map[string]any) (T, error)) func(string, map[string]any) (sdk.StepInstance, error) {
	return func(name string, config map[string]any) (sdk.StepInstance, error) {
		return ctor(name, config)
	}
}
