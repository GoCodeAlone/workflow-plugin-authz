package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_resource_instance_create ---

type permitResourceInstanceCreateStep struct {
	name       string
	moduleName string
}

func newPermitResourceInstanceCreateStep(name string, config map[string]any) (*permitResourceInstanceCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceInstanceCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceInstanceCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "tenant", "resource"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("resource_instances"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_instance_get ---

type permitResourceInstanceGetStep struct {
	name       string
	moduleName string
}

func newPermitResourceInstanceGetStep(name string, config map[string]any) (*permitResourceInstanceGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceInstanceGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceInstanceGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	instanceID := resolvePermitValue("instance_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitFactsPath("resource_instances/"+instanceID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_instance_list ---

type permitResourceInstanceListStep struct {
	name       string
	moduleName string
}

func newPermitResourceInstanceListStep(name string, config map[string]any) (*permitResourceInstanceListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceInstanceListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceInstanceListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("resource_instances"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"resource_instances": result}}, nil
}

// --- step.permit_resource_instance_update ---

type permitResourceInstanceUpdateStep struct {
	name       string
	moduleName string
}

func newPermitResourceInstanceUpdateStep(name string, config map[string]any) (*permitResourceInstanceUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceInstanceUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceInstanceUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	instanceID := resolvePermitValue("instance_id", current, config)
	body := map[string]any{}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitFactsPath("resource_instances/"+instanceID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_instance_delete ---

type permitResourceInstanceDeleteStep struct {
	name       string
	moduleName string
}

func newPermitResourceInstanceDeleteStep(name string, config map[string]any) (*permitResourceInstanceDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceInstanceDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceInstanceDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	instanceID := resolvePermitValue("instance_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("resource_instances/"+instanceID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "instance_id": instanceID}}, nil
}
