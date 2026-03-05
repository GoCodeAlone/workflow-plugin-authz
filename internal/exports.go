package internal

import (
	"context"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// StepExecutor is the interface satisfied by all internal step types.
// It matches sdk.StepInstance.Execute but is defined here to avoid leaking
// the SDK type into the public authz/ package API.
type StepExecutor interface {
	Execute(
		ctx context.Context,
		triggerData map[string]any,
		stepOutputs map[string]map[string]any,
		current map[string]any,
		metadata map[string]any,
		config map[string]any,
	) (*sdk.StepResult, error)
}

// NewCasbinModuleFromConfig creates a CasbinModule from raw config.
// Exported for use by the public authz/ package.
func NewCasbinModuleFromConfig(name string, config map[string]any) (*CasbinModule, error) {
	return newCasbinModule(name, config)
}

// NewCasbinCheckStep creates a step.authz_check_casbin step instance.
func NewCasbinCheckStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzCheckStep(name, config)
}

// NewAddPolicyStep creates a step.authz_add_policy step instance.
func NewAddPolicyStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzAddPolicyStep(name, config)
}

// NewRemovePolicyStep creates a step.authz_remove_policy step instance.
func NewRemovePolicyStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzRemovePolicyStep(name, config)
}

// NewRoleAssignStep creates a step.authz_role_assign step instance.
func NewRoleAssignStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzRoleAssignStep(name, config)
}
