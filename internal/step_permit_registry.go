package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// permitStepConstructors maps step type names to their constructor functions.
// All constructors have the signature: func(name string, config map[string]any) (sdk.StepInstance, error)
var permitStepConstructors = map[string]func(string, map[string]any) (sdk.StepInstance, error){
	// Authorization checks
	"step.permit_check":             wrapPermitStep(newPermitCheckStep),
	"step.permit_check_bulk":        wrapPermitStep(newPermitCheckBulkStep),
	"step.permit_user_permissions":  wrapPermitStep(newPermitUserPermissionsStep),
	"step.permit_authorized_users":  wrapPermitStep(newPermitAuthorizedUsersStep),

	// User management
	"step.permit_user_create":    wrapPermitStep(newPermitUserCreateStep),
	"step.permit_user_get":       wrapPermitStep(newPermitUserGetStep),
	"step.permit_user_list":      wrapPermitStep(newPermitUserListStep),
	"step.permit_user_update":    wrapPermitStep(newPermitUserUpdateStep),
	"step.permit_user_delete":    wrapPermitStep(newPermitUserDeleteStep),
	"step.permit_user_sync":      wrapPermitStep(newPermitUserSyncStep),
	"step.permit_user_get_roles": wrapPermitStep(newPermitUserGetRolesStep),

	// Tenant management
	"step.permit_tenant_create":     wrapPermitStep(newPermitTenantCreateStep),
	"step.permit_tenant_get":        wrapPermitStep(newPermitTenantGetStep),
	"step.permit_tenant_list":       wrapPermitStep(newPermitTenantListStep),
	"step.permit_tenant_update":     wrapPermitStep(newPermitTenantUpdateStep),
	"step.permit_tenant_delete":     wrapPermitStep(newPermitTenantDeleteStep),
	"step.permit_tenant_list_users": wrapPermitStep(newPermitTenantListUsersStep),

	// Role management
	"step.permit_role_create":             wrapPermitStep(newPermitRoleCreateStep),
	"step.permit_role_get":                wrapPermitStep(newPermitRoleGetStep),
	"step.permit_role_list":               wrapPermitStep(newPermitRoleListStep),
	"step.permit_role_update":             wrapPermitStep(newPermitRoleUpdateStep),
	"step.permit_role_delete":             wrapPermitStep(newPermitRoleDeleteStep),
	"step.permit_role_assign_permissions": wrapPermitStep(newPermitRoleAssignPermissionsStep),
	"step.permit_role_remove_permissions": wrapPermitStep(newPermitRoleRemovePermissionsStep),

	// Role assignments
	"step.permit_role_assign":          wrapPermitStep(newPermitRoleAssignStep),
	"step.permit_role_unassign":        wrapPermitStep(newPermitRoleUnassignStep),
	"step.permit_role_assignment_list": wrapPermitStep(newPermitRoleAssignmentListStep),
	"step.permit_bulk_assign":          wrapPermitStep(newPermitBulkAssignStep),
	"step.permit_bulk_unassign":        wrapPermitStep(newPermitBulkUnassignStep),

	// Resource management
	"step.permit_resource_create": wrapPermitStep(newPermitResourceCreateStep),
	"step.permit_resource_get":    wrapPermitStep(newPermitResourceGetStep),
	"step.permit_resource_list":   wrapPermitStep(newPermitResourceListStep),
	"step.permit_resource_update": wrapPermitStep(newPermitResourceUpdateStep),
	"step.permit_resource_delete": wrapPermitStep(newPermitResourceDeleteStep),

	// Resource actions
	"step.permit_resource_action_create": wrapPermitStep(newPermitResourceActionCreateStep),
	"step.permit_resource_action_get":    wrapPermitStep(newPermitResourceActionGetStep),
	"step.permit_resource_action_list":   wrapPermitStep(newPermitResourceActionListStep),
	"step.permit_resource_action_update": wrapPermitStep(newPermitResourceActionUpdateStep),
	"step.permit_resource_action_delete": wrapPermitStep(newPermitResourceActionDeleteStep),

	// Resource roles
	"step.permit_resource_role_create": wrapPermitStep(newPermitResourceRoleCreateStep),
	"step.permit_resource_role_get":    wrapPermitStep(newPermitResourceRoleGetStep),
	"step.permit_resource_role_list":   wrapPermitStep(newPermitResourceRoleListStep),
	"step.permit_resource_role_update": wrapPermitStep(newPermitResourceRoleUpdateStep),
	"step.permit_resource_role_delete": wrapPermitStep(newPermitResourceRoleDeleteStep),

	// ReBAC relations
	"step.permit_resource_relation_create": wrapPermitStep(newPermitResourceRelationCreateStep),
	"step.permit_resource_relation_list":   wrapPermitStep(newPermitResourceRelationListStep),
	"step.permit_resource_relation_delete": wrapPermitStep(newPermitResourceRelationDeleteStep),

	// Resource instances
	"step.permit_resource_instance_create": wrapPermitStep(newPermitResourceInstanceCreateStep),
	"step.permit_resource_instance_get":    wrapPermitStep(newPermitResourceInstanceGetStep),
	"step.permit_resource_instance_list":   wrapPermitStep(newPermitResourceInstanceListStep),
	"step.permit_resource_instance_update": wrapPermitStep(newPermitResourceInstanceUpdateStep),
	"step.permit_resource_instance_delete": wrapPermitStep(newPermitResourceInstanceDeleteStep),

	// Relationship tuples
	"step.permit_relationship_tuple_create":      wrapPermitStep(newPermitRelationshipTupleCreateStep),
	"step.permit_relationship_tuple_delete":      wrapPermitStep(newPermitRelationshipTupleDeleteStep),
	"step.permit_relationship_tuple_list":        wrapPermitStep(newPermitRelationshipTupleListStep),
	"step.permit_relationship_tuple_bulk_create": wrapPermitStep(newPermitRelationshipTupleBulkCreateStep),
	"step.permit_relationship_tuple_bulk_delete": wrapPermitStep(newPermitRelationshipTupleBulkDeleteStep),

	// ABAC condition sets
	"step.permit_condition_set_create": wrapPermitStep(newPermitConditionSetCreateStep),
	"step.permit_condition_set_get":    wrapPermitStep(newPermitConditionSetGetStep),
	"step.permit_condition_set_list":   wrapPermitStep(newPermitConditionSetListStep),
	"step.permit_condition_set_update": wrapPermitStep(newPermitConditionSetUpdateStep),
	"step.permit_condition_set_delete": wrapPermitStep(newPermitConditionSetDeleteStep),

	// Project management
	"step.permit_project_create": wrapPermitStep(newPermitProjectCreateStep),
	"step.permit_project_get":    wrapPermitStep(newPermitProjectGetStep),
	"step.permit_project_list":   wrapPermitStep(newPermitProjectListStep),
	"step.permit_project_update": wrapPermitStep(newPermitProjectUpdateStep),
	"step.permit_project_delete": wrapPermitStep(newPermitProjectDeleteStep),

	// Environment management
	"step.permit_env_create": wrapPermitStep(newPermitEnvCreateStep),
	"step.permit_env_get":    wrapPermitStep(newPermitEnvGetStep),
	"step.permit_env_list":   wrapPermitStep(newPermitEnvListStep),
	"step.permit_env_update": wrapPermitStep(newPermitEnvUpdateStep),
	"step.permit_env_delete": wrapPermitStep(newPermitEnvDeleteStep),
	"step.permit_env_copy":   wrapPermitStep(newPermitEnvCopyStep),

	// API key management
	"step.permit_api_key_create": wrapPermitStep(newPermitAPIKeyCreateStep),
	"step.permit_api_key_list":   wrapPermitStep(newPermitAPIKeyListStep),
	"step.permit_api_key_delete": wrapPermitStep(newPermitAPIKeyDeleteStep),
	"step.permit_api_key_rotate": wrapPermitStep(newPermitAPIKeyRotateStep),

	// Organization management
	"step.permit_org_get":           wrapPermitStep(newPermitOrgGetStep),
	"step.permit_org_update":        wrapPermitStep(newPermitOrgUpdateStep),
	"step.permit_org_member_list":   wrapPermitStep(newPermitOrgMemberListStep),
	"step.permit_org_member_invite": wrapPermitStep(newPermitOrgMemberInviteStep),
	"step.permit_org_member_remove": wrapPermitStep(newPermitOrgMemberRemoveStep),
}

// createPermitStep dispatches to the appropriate permit step constructor.
func createPermitStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	ctor, ok := permitStepConstructors[typeName]
	if !ok {
		return nil, fmt.Errorf("authz plugin: unknown permit step type %q", typeName)
	}
	return ctor(name, config)
}

// permitStepTypes returns all registered permit step type names.
func permitStepTypes() []string {
	types := make([]string, 0, len(permitStepConstructors))
	for k := range permitStepConstructors {
		types = append(types, k)
	}
	return types
}

// wrapPermitStep adapts a typed constructor to the generic sdk.StepInstance interface.
func wrapPermitStep[T sdk.StepInstance](ctor func(string, map[string]any) (T, error)) func(string, map[string]any) (sdk.StepInstance, error) {
	return func(name string, config map[string]any) (sdk.StepInstance, error) {
		return ctor(name, config)
	}
}
