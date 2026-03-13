package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_user_create ---

type permitUserCreateStep struct {
	name       string
	moduleName string
}

func newPermitUserCreateStep(name string, config map[string]any) (*permitUserCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "email", "first_name", "last_name", "attributes"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("users"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_user_get ---

type permitUserGetStep struct {
	name       string
	moduleName string
}

func newPermitUserGetStep(name string, config map[string]any) (*permitUserGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userID := resolvePermitValue("user_id", current, config)
	result, err := client.doAPI(ctx, http.MethodGet, client.permitFactsPath("users/"+userID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_user_list ---

type permitUserListStep struct {
	name       string
	moduleName string
}

func newPermitUserListStep(name string, config map[string]any) (*permitUserListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("users"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"users": result}}, nil
}

// --- step.permit_user_update ---

type permitUserUpdateStep struct {
	name       string
	moduleName string
}

func newPermitUserUpdateStep(name string, config map[string]any) (*permitUserUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userID := resolvePermitValue("user_id", current, config)
	body := map[string]any{}
	for _, k := range []string{"email", "first_name", "last_name"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPatch, client.permitFactsPath("users/"+userID), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_user_delete ---

type permitUserDeleteStep struct {
	name       string
	moduleName string
}

func newPermitUserDeleteStep(name string, config map[string]any) (*permitUserDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userID := resolvePermitValue("user_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("users/"+userID), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true, "user_id": userID}}, nil
}

// --- step.permit_user_sync ---

type permitUserSyncStep struct {
	name       string
	moduleName string
}

func newPermitUserSyncStep(name string, config map[string]any) (*permitUserSyncStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserSyncStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserSyncStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"key", "email", "first_name", "last_name"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}
	if attrs, ok := config["attributes"].(map[string]any); ok {
		body["attributes"] = attrs
	}

	result, err := client.doAPI(ctx, http.MethodPut, client.permitFactsPath("users"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_user_get_roles ---

type permitUserGetRolesStep struct {
	name       string
	moduleName string
}

func newPermitUserGetRolesStep(name string, config map[string]any) (*permitUserGetRolesStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitUserGetRolesStep{name: name, moduleName: moduleName}, nil
}

func (s *permitUserGetRolesStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	userID := resolvePermitValue("user_id", current, config)
	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("users/"+userID+"/roles"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"roles": result}}, nil
}
