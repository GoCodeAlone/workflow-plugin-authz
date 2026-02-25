// Package internal implements the workflow-plugin-authz plugin, providing
// Casbin-based RBAC authorization as a module and pipeline step.
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
		Description: "RBAC authorization plugin using Casbin",
	}
}

// ModuleTypes returns the module type names this plugin provides.
func (p *authzPlugin) ModuleTypes() []string {
	return []string{"authz.casbin"}
}

// CreateModule creates a module instance of the given type and registers it
// in the global registry so that step.authz_check can locate it by name.
func (p *authzPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "authz.casbin":
		m, err := newCasbinModule(name, config)
		if err != nil {
			return nil, err
		}
		RegisterModule(m)
		return m, nil
	default:
		return nil, fmt.Errorf("authz plugin: unknown module type %q", typeName)
	}
}

// StepTypes returns the step type names this plugin provides.
func (p *authzPlugin) StepTypes() []string {
	return []string{"step.authz_check"}
}

// CreateStep creates a step instance of the given type.
func (p *authzPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.authz_check":
		return newAuthzCheckStep(name, config)
	default:
		return nil, fmt.Errorf("authz plugin: unknown step type %q", typeName)
	}
}
