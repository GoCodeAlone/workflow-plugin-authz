package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_resource_action_create ---

type permitResourceActionCreateStep struct {
	name       string
	moduleName string
}

func newPermitResourceActionCreateStep(name string, config map[string]any) (*permitResourceActionCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceActionCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceActionCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
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

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("resources/"+resourceID+"/actions"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_action_get ---

type permitResourceActionGetStep struct {
	name       string
	moduleName string
}

func newPermitResourceActionGetStep(name string, config map[string]any) (*permitResourceActionGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceActionGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceActionGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	actionID := resolvePermitValue("action_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID+"/actions/"+actionID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_action_list ---

type permitResourceActionListStep struct {
	name       string
	moduleName string
}

func newPermitResourceActionListStep(name string, config map[string]any) (*permitResourceActionListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceActionListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceActionListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID+"/actions"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"actions": result}}, nil
}

// --- step.permit_resource_action_update ---

type permitResourceActionUpdateStep struct {
	name       string
	moduleName string
}

func newPermitResourceActionUpdateStep(name string, config map[string]any) (*permitResourceActionUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceActionUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceActionUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	actionID := resolvePermitValue("action_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitSchemaPath("resources/"+resourceID+"/actions/"+actionID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_action_delete ---

type permitResourceActionDeleteStep struct {
	name       string
	moduleName string
}

func newPermitResourceActionDeleteStep(name string, config map[string]any) (*permitResourceActionDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceActionDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceActionDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	actionID := resolvePermitValue("action_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("resources/"+resourceID+"/actions/"+actionID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "action_id": actionID}}, nil
}
