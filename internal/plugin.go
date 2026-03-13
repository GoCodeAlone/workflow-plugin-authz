// Package internal implements the workflow-plugin-authz plugin, providing
// Casbin-based RBAC authorization and Permit.io authorization as modules and pipeline steps.
package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// authzPlugin implements sdk.PluginProvider, sdk.ModuleProvider, and sdk.StepProvider.
type authzPlugin struct{}

// NewAuthzPlugin returns a new authzPlugin instance.
func NewAuthzPlugin() sdk.PluginProvider {
	return &authzPlugin{}
}

// Manifest returns plugin metadata.
func (p *authzPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-authz",
		Version:     "1.0.0",
		Author:      "GoCodeAlone",
		Description: "RBAC authorization plugin using Casbin and Permit.io",
	}
}

// ModuleTypes returns the module type names this plugin provides.
func (p *authzPlugin) ModuleTypes() []string {
	return []string{"authz.casbin", "permit.provider"}
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

// StepTypes returns the step type names this plugin provides.
func (p *authzPlugin) StepTypes() []string {
	casbinSteps := []string{
		"step.authz_check_casbin",
		"step.authz_add_policy",
		"step.authz_remove_policy",
		"step.authz_role_assign",
	}
	return append(casbinSteps, permitStepTypes()...)
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
	default:
		// Delegate to permit step registry for all step.permit_* types.
		if step, err := createPermitStep(typeName, name, config); err == nil {
			return step, nil
		}
		return nil, fmt.Errorf("authz plugin: unknown step type %q", typeName)
	}
}
