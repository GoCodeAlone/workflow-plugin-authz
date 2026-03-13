package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_check ---

type permitCheckStep struct {
	name       string
	moduleName string
}

func newPermitCheckStep(name string, config map[string]any) (*permitCheckStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitCheckStep{name: name, moduleName: moduleName}, nil
}

func (s *permitCheckStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userKey := resolvePermitValue("user", current, config)
	action := resolvePermitValue("action", current, config)
	resourceType := resolvePermitValue("resource_type", current, config)
	resourceKey := resolvePermitValue("resource_key", current, config)
	tenant := resolvePermitValue("tenant", current, config)

	body := map[string]any{
		"user":   map[string]any{"key": userKey},
		"action": action,
		"resource": map[string]any{
			"type":   resourceType,
			"key":    resourceKey,
			"tenant": tenant,
		},
	}

	result, err := client.doPDP(ctx, http.MethodPost, "/allowed", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_check_bulk ---

type permitCheckBulkStep struct {
	name       string
	moduleName string
}

func newPermitCheckBulkStep(name string, config map[string]any) (*permitCheckBulkStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitCheckBulkStep{name: name, moduleName: moduleName}, nil
}

func (s *permitCheckBulkStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	checks, _ := config["checks"].([]any)
	if checks == nil {
		checks, _ = current["checks"].([]any)
	}

	result, err := client.doPDP(ctx, http.MethodPost, "/allowed/bulk", checks)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_user_permissions ---

type permitUserPermissionsStep struct {
	name       string
	moduleName string
}

func newPermitUserPermissionsStep(name string, config map[string]any) (*permitUserPermissionsStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserPermissionsStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserPermissionsStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userKey := resolvePermitValue("user_key", current, config)
	result, err := client.doPDP(ctx, http.MethodGet, "/v2/pdp/user_permissions/"+userKey, nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_authorized_users ---

type permitAuthorizedUsersStep struct {
	name       string
	moduleName string
}

func newPermitAuthorizedUsersStep(name string, config map[string]any) (*permitAuthorizedUsersStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitAuthorizedUsersStep{name: name, moduleName: moduleName}, nil
}

func (s *permitAuthorizedUsersStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	action := resolvePermitValue("action", current, config)
	resourceType := resolvePermitValue("resource_type", current, config)
	resourceKey := resolvePermitValue("resource_key", current, config)

	body := map[string]any{
		"action": action,
		"resource": map[string]any{
			"type": resourceType,
			"key":  resourceKey,
		},
	}

	result, err := client.doPDP(ctx, http.MethodPost, "/authorized_users", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}
