package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_tenant_create ---

type permitTenantCreateStep struct {
	name       string
	moduleName string
}

func newPermitTenantCreateStep(name string, config map[string]any) (*permitTenantCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
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
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("tenants"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_tenant_get ---

type permitTenantGetStep struct {
	name       string
	moduleName string
}

func newPermitTenantGetStep(name string, config map[string]any) (*permitTenantGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tenantID := resolvePermitValue("tenant_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitFactsPath("tenants/"+tenantID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_tenant_list ---

type permitTenantListStep struct {
	name       string
	moduleName string
}

func newPermitTenantListStep(name string, config map[string]any) (*permitTenantListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("tenants"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"tenants": result}}, nil
}

// --- step.permit_tenant_update ---

type permitTenantUpdateStep struct {
	name       string
	moduleName string
}

func newPermitTenantUpdateStep(name string, config map[string]any) (*permitTenantUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tenantID := resolvePermitValue("tenant_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitFactsPath("tenants/"+tenantID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_tenant_delete ---

type permitTenantDeleteStep struct {
	name       string
	moduleName string
}

func newPermitTenantDeleteStep(name string, config map[string]any) (*permitTenantDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tenantID := resolvePermitValue("tenant_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("tenants/"+tenantID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "tenant_id": tenantID}}, nil
}

// --- step.permit_tenant_list_users ---

type permitTenantListUsersStep struct {
	name       string
	moduleName string
}

func newPermitTenantListUsersStep(name string, config map[string]any) (*permitTenantListUsersStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitTenantListUsersStep{name: name, moduleName: moduleName}, nil
}

func (s *permitTenantListUsersStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tenantID := resolvePermitValue("tenant_id", current, config)
	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("tenants/"+tenantID+"/users"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"users": result}}, nil
}
