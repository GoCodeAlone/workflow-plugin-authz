package internal

import (
	"context"
	"fmt"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_api_key_create ---

type permitAPIKeyCreateStep struct {
	name       string
	moduleName string
}

func newPermitAPIKeyCreateStep(name string, config map[string]any) (*permitAPIKeyCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitAPIKeyCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitAPIKeyCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"object_type", "project_id", "environment_id", "organization_id"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, "/v2/api-key", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_api_key_list ---

type permitAPIKeyListStep struct {
	name       string
	moduleName string
}

func newPermitAPIKeyListStep(name string, config map[string]any) (*permitAPIKeyListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitAPIKeyListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitAPIKeyListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, "/v2/api-key", nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"api_keys": result}}, nil
}

// --- step.permit_api_key_delete ---

type permitAPIKeyDeleteStep struct {
	name       string
	moduleName string
}

func newPermitAPIKeyDeleteStep(name string, config map[string]any) (*permitAPIKeyDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitAPIKeyDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitAPIKeyDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	keyID := resolvePermitValue("key_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, "/v2/api-key/"+keyID, nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "key_id": keyID}}, nil
}

// --- step.permit_api_key_rotate ---

type permitAPIKeyRotateStep struct {
	name       string
	moduleName string
}

func newPermitAPIKeyRotateStep(name string, config map[string]any) (*permitAPIKeyRotateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitAPIKeyRotateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitAPIKeyRotateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	keyID := resolvePermitValue("key_id", current, config)
	result, err := client.doAPI(ctx, http.MethodPost, fmt.Sprintf("/v2/api-key/%s/rotate", keyID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}
