package internal

import (
	"context"
	"fmt"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_env_create ---

type permitEnvCreateStep struct {
	name       string
	moduleName string
}

func newPermitEnvCreateStep(name string, config map[string]any) (*permitEnvCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	body := map[string]any{}
	for _, k := range []string{"key", "name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, fmt.Sprintf("/v2/projects/%s/envs", projectID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_env_get ---

type permitEnvGetStep struct {
	name       string
	moduleName string
}

func newPermitEnvGetStep(name string, config map[string]any) (*permitEnvGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	envID := resolvePermitValue("env_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, fmt.Sprintf("/v2/projects/%s/envs/%s", projectID, envID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_env_list ---

type permitEnvListStep struct {
	name       string
	moduleName string
}

func newPermitEnvListStep(name string, config map[string]any) (*permitEnvListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	result, err := client.doAPIList(ctx, http.MethodGet, fmt.Sprintf("/v2/projects/%s/envs", projectID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"environments": result}}, nil
}

// --- step.permit_env_update ---

type permitEnvUpdateStep struct {
	name       string
	moduleName string
}

func newPermitEnvUpdateStep(name string, config map[string]any) (*permitEnvUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	envID := resolvePermitValue("env_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"name", "description"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, fmt.Sprintf("/v2/projects/%s/envs/%s", projectID, envID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_env_delete ---

type permitEnvDeleteStep struct {
	name       string
	moduleName string
}

func newPermitEnvDeleteStep(name string, config map[string]any) (*permitEnvDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	envID := resolvePermitValue("env_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, fmt.Sprintf("/v2/projects/%s/envs/%s", projectID, envID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "env_id": envID}}, nil
}

// --- step.permit_env_copy ---

type permitEnvCopyStep struct {
	name       string
	moduleName string
}

func newPermitEnvCopyStep(name string, config map[string]any) (*permitEnvCopyStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitEnvCopyStep{name: name, moduleName: moduleName}, nil
}

func (s *permitEnvCopyStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	projectID := resolvePermitValue("project_id", current, config)
	if projectID == "" {
		projectID = client.project
	}
	envID := resolvePermitValue("env_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"key", "name", "description", "scope"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if targetEnv, ok := config["target_env"].(map[string]any); ok {
		body["target_env"] = targetEnv
	}

	result, err := client.doAPI(ctx, http.MethodPost, fmt.Sprintf("/v2/projects/%s/envs/%s/copy", projectID, envID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}
