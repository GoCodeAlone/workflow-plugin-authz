package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_resource_create ---

type permitResourceCreateStep struct {
	name       string
	moduleName string
}

func newPermitResourceCreateStep(name string, config map[string]any) (*permitResourceCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "name", "description", "urn"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if actions, ok := config["actions"].(map[string]any); ok {
		body["actions"] = actions
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("resources"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_get ---

type permitResourceGetStep struct {
	name       string
	moduleName string
}

func newPermitResourceGetStep(name string, config map[string]any) (*permitResourceGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_list ---

type permitResourceListStep struct {
	name       string
	moduleName string
}

func newPermitResourceListStep(name string, config map[string]any) (*permitResourceListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("resources"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"resources": result}}, nil
}

// --- step.permit_resource_update ---

type permitResourceUpdateStep struct {
	name       string
	moduleName string
}

func newPermitResourceUpdateStep(name string, config map[string]any) (*permitResourceUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description", "urn"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if actions, ok := config["actions"].(map[string]any); ok {
		body["actions"] = actions
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitSchemaPath("resources/"+resourceID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_delete ---

type permitResourceDeleteStep struct {
	name       string
	moduleName string
}

func newPermitResourceDeleteStep(name string, config map[string]any) (*permitResourceDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("resources/"+resourceID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "resource_id": resourceID}}, nil
}
