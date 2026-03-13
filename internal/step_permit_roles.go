package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_role_create ---

type permitRoleCreateStep struct {
	name       string
	moduleName string
}

func newPermitRoleCreateStep(name string, config map[string]any) (*permitRoleCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if perms, ok := config["permissions"].([]any); ok {
		body["permissions"] = perms
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("roles"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_role_get ---

type permitRoleGetStep struct {
	name       string
	moduleName string
}

func newPermitRoleGetStep(name string, config map[string]any) (*permitRoleGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	roleID := resolvePermitValue("role_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitSchemaPath("roles/"+roleID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_role_list ---

type permitRoleListStep struct {
	name       string
	moduleName string
}

func newPermitRoleListStep(name string, config map[string]any) (*permitRoleListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("roles"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"roles": result}}, nil
}

// --- step.permit_role_update ---

type permitRoleUpdateStep struct {
	name       string
	moduleName string
}

func newPermitRoleUpdateStep(name string, config map[string]any) (*permitRoleUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	roleID := resolvePermitValue("role_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitSchemaPath("roles/"+roleID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_role_delete ---

type permitRoleDeleteStep struct {
	name       string
	moduleName string
}

func newPermitRoleDeleteStep(name string, config map[string]any) (*permitRoleDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	roleID := resolvePermitValue("role_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("roles/"+roleID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "role_id": roleID}}, nil
}

// --- step.permit_role_assign_permissions ---

type permitRoleAssignPermissionsStep struct {
	name       string
	moduleName string
}

func newPermitRoleAssignPermissionsStep(name string, config map[string]any) (*permitRoleAssignPermissionsStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleAssignPermissionsStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleAssignPermissionsStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	roleID := resolvePermitValue("role_id", current, config)
	perms, _ := config["permissions"].([]any)
	body := map[string]any{"permissions": perms}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("roles/"+roleID+"/permissions"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_role_remove_permissions ---

type permitRoleRemovePermissionsStep struct {
	name       string
	moduleName string
}

func newPermitRoleRemovePermissionsStep(name string, config map[string]any) (*permitRoleRemovePermissionsStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleRemovePermissionsStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleRemovePermissionsStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	roleID := resolvePermitValue("role_id", current, config)
	perms, _ := config["permissions"].([]any)
	body := map[string]any{"permissions": perms}

	result, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("roles/"+roleID+"/permissions"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}
