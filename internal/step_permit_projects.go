package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_project_create ---

type permitProjectCreateStep struct {
	name       string
	moduleName string
}

func newPermitProjectCreateStep(name string, config map[string]any) (*permitProjectCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitProjectCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitProjectCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
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

	result, err := client.doAPI(ctx, http.MethodPost, "/v2/projects", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_project_get ---

type permitProjectGetStep struct {
	name       string
	moduleName string
}

func newPermitProjectGetStep(name string, config map[string]any) (*permitProjectGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitProjectGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitProjectGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, "/v2/projects/"+projectID, nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_project_list ---

type permitProjectListStep struct {
	name       string
	moduleName string
}

func newPermitProjectListStep(name string, config map[string]any) (*permitProjectListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitProjectListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitProjectListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, "/v2/projects", nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"projects": result}}, nil
}

// --- step.permit_project_update ---

type permitProjectUpdateStep struct {
	name       string
	moduleName string
}

func newPermitProjectUpdateStep(name string, config map[string]any) (*permitProjectUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitProjectUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitProjectUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, "/v2/projects/"+projectID, body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_project_delete ---

type permitProjectDeleteStep struct {
	name       string
	moduleName string
}

func newPermitProjectDeleteStep(name string, config map[string]any) (*permitProjectDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitProjectDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitProjectDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, "/v2/projects/"+projectID, nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "project_id": projectID}}, nil
}
