package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_condition_set_create ---

type permitConditionSetCreateStep struct {
	name       string
	moduleName string
}

func newPermitConditionSetCreateStep(name string, config map[string]any) (*permitConditionSetCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitConditionSetCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitConditionSetCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "name", "description", "type"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if conditions, ok := config["conditions"].(map[string]any); ok {
		body["conditions"] = conditions
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("condition_sets"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_condition_set_get ---

type permitConditionSetGetStep struct {
	name       string
	moduleName string
}

func newPermitConditionSetGetStep(name string, config map[string]any) (*permitConditionSetGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitConditionSetGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitConditionSetGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	conditionSetID := resolvePermitValue("condition_set_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitSchemaPath("condition_sets/"+conditionSetID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_condition_set_list ---

type permitConditionSetListStep struct {
	name       string
	moduleName string
}

func newPermitConditionSetListStep(name string, config map[string]any) (*permitConditionSetListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitConditionSetListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitConditionSetListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("condition_sets"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"condition_sets": result}}, nil
}

// --- step.permit_condition_set_update ---

type permitConditionSetUpdateStep struct {
	name       string
	moduleName string
}

func newPermitConditionSetUpdateStep(name string, config map[string]any) (*permitConditionSetUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitConditionSetUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitConditionSetUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	conditionSetID := resolvePermitValue("condition_set_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if conditions, ok := config["conditions"].(map[string]any); ok {
		body["conditions"] = conditions
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitSchemaPath("condition_sets/"+conditionSetID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_condition_set_delete ---

type permitConditionSetDeleteStep struct {
	name       string
	moduleName string
}

func newPermitConditionSetDeleteStep(name string, config map[string]any) (*permitConditionSetDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitConditionSetDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitConditionSetDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	conditionSetID := resolvePermitValue("condition_set_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("condition_sets/"+conditionSetID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "condition_set_id": conditionSetID}}, nil
}
