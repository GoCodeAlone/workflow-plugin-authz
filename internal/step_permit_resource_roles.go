package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_resource_role_create ---

type permitResourceRoleCreateStep struct {
	name       string
	moduleName string
}

func newPermitResourceRoleCreateStep(name string, config map[string]any) (*permitResourceRoleCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRoleCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRoleCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"key", "name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if perms, ok := config["permissions"].([]any); ok {
		body["permissions"] = perms
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("resources/"+resourceID+"/roles"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_role_get ---

type permitResourceRoleGetStep struct {
	name       string
	moduleName string
}

func newPermitResourceRoleGetStep(name string, config map[string]any) (*permitResourceRoleGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRoleGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRoleGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	roleID := resolvePermitValue("role_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID+"/roles/"+roleID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_role_list ---

type permitResourceRoleListStep struct {
	name       string
	moduleName string
}

func newPermitResourceRoleListStep(name string, config map[string]any) (*permitResourceRoleListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRoleListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRoleListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID+"/roles"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"roles": result}}, nil
}

// --- step.permit_resource_role_update ---

type permitResourceRoleUpdateStep struct {
	name       string
	moduleName string
}

func newPermitResourceRoleUpdateStep(name string, config map[string]any) (*permitResourceRoleUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRoleUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRoleUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	roleID := resolvePermitValue("role_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitSchemaPath("resources/"+resourceID+"/roles/"+roleID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_role_delete ---

type permitResourceRoleDeleteStep struct {
	name       string
	moduleName string
}

func newPermitResourceRoleDeleteStep(name string, config map[string]any) (*permitResourceRoleDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRoleDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRoleDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	roleID := resolvePermitValue("role_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("resources/"+resourceID+"/roles/"+roleID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "role_id": roleID}}, nil
}
