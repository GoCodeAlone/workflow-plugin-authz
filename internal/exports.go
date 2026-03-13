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

// NewPermitModuleFromConfig creates a PermitModule from raw config.
// Exported for use by the public authz/ package.
func NewPermitModuleFromConfig(name string, config map[string]any) (*PermitModule, error) {
	return newPermitModule(name, config)
}

// NewPermitCheckStep creates a step.permit_check step instance.
func NewPermitCheckStep(name string, config map[string]any) (StepExecutor, error) {
	return newPermitCheckStep(name, config)
}

// NewPermitCheckBulkStep creates a step.permit_check_bulk step instance.
func NewPermitCheckBulkStep(name string, config map[string]any) (StepExecutor, error) {
	return newPermitCheckBulkStep(name, config)
}

// NewAuthzCapabilitiesStep creates a step.authz_capabilities step instance.
func NewAuthzCapabilitiesStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzCapabilitiesStep(name, config)
}

// NewAuthzACLGrantStep creates a step.authz_acl_grant step instance.
func NewAuthzACLGrantStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzACLGrantStep(name, config)
}

// NewAuthzACLRevokeStep creates a step.authz_acl_revoke step instance.
func NewAuthzACLRevokeStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzACLRevokeStep(name, config)
}

// NewAuthzACLCheckStep creates a step.authz_acl_check step instance.
func NewAuthzACLCheckStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzACLCheckStep(name, config)
}

// NewAuthzACLListStep creates a step.authz_acl_list step instance.
func NewAuthzACLListStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzACLListStep(name, config)
}

// NewAuthzABACCheckStep creates a step.authz_abac_check step instance.
func NewAuthzABACCheckStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzABACCheckStep(name, config)
}

// NewAuthzABACAddPolicyStep creates a step.authz_abac_add_policy step instance.
func NewAuthzABACAddPolicyStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzABACAddPolicyStep(name, config)
}

// NewAuthzReBACAddRelationStep creates a step.authz_rebac_add_relation step instance.
func NewAuthzReBACAddRelationStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzReBACAddRelationStep(name, config)
}

// NewAuthzReBACRemoveRelationStep creates a step.authz_rebac_remove_relation step instance.
func NewAuthzReBACRemoveRelationStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzReBACRemoveRelationStep(name, config)
}

// NewAuthzReBACCheckStep creates a step.authz_rebac_check step instance.
func NewAuthzReBACCheckStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzReBACCheckStep(name, config)
}

// NewAuthzReBACListRelationsStep creates a step.authz_rebac_list_relations step instance.
func NewAuthzReBACListRelationsStep(name string, config map[string]any) (StepExecutor, error) {
	return newAuthzReBACListRelationsStep(name, config)
}

// NewPermitUserSyncStep creates a step.permit_user_sync step instance.
func NewPermitUserSyncStep(name string, config map[string]any) (StepExecutor, error) {
	return newPermitUserSyncStep(name, config)
}

// NewPermitRoleAssignStep creates a step.permit_role_assign step instance.
func NewPermitRoleAssignStep(name string, config map[string]any) (StepExecutor, error) {
	return newPermitRoleAssignStep(name, config)
}

// NewPermitRoleUnassignStep creates a step.permit_role_unassign step instance.
func NewPermitRoleUnassignStep(name string, config map[string]any) (StepExecutor, error) {
	return newPermitRoleUnassignStep(name, config)
}
