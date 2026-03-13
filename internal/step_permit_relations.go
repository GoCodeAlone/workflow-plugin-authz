package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_resource_relation_create ---

type permitResourceRelationCreateStep struct {
	name       string
	moduleName string
}

func newPermitResourceRelationCreateStep(name string, config map[string]any) (*permitResourceRelationCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRelationCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRelationCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"key", "name", "subject_resource"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitSchemaPath("resources/"+resourceID+"/relations"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_resource_relation_list ---

type permitResourceRelationListStep struct {
	name       string
	moduleName string
}

func newPermitResourceRelationListStep(name string, config map[string]any) (*permitResourceRelationListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRelationListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRelationListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	result, err := client.doAPIList(ctx, http.MethodGet, client.permitSchemaPath("resources/"+resourceID+"/relations"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"relations": result}}, nil
}

// --- step.permit_resource_relation_delete ---

type permitResourceRelationDeleteStep struct {
	name       string
	moduleName string
}

func newPermitResourceRelationDeleteStep(name string, config map[string]any) (*permitResourceRelationDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitResourceRelationDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitResourceRelationDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	resourceID := resolvePermitValue("resource_id", current, config)
	relationID := resolvePermitValue("relation_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitSchemaPath("resources/"+resourceID+"/relations/"+relationID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "relation_id": relationID}}, nil
}
