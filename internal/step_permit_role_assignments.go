package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_role_assign ---

type permitRoleAssignStep struct {
	name       string
	moduleName string
}

func newPermitRoleAssignStep(name string, config map[string]any) (*permitRoleAssignStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleAssignStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleAssignStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"user", "role", "tenant", "resource_instance"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("role_assignments"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_role_unassign ---

type permitRoleUnassignStep struct {
	name       string
	moduleName string
}

func newPermitRoleUnassignStep(name string, config map[string]any) (*permitRoleUnassignStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleUnassignStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleUnassignStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"user", "role", "tenant", "resource_instance"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("role_assignments"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"unassigned": true}}, nil
}

// --- step.permit_role_assignment_list ---

type permitRoleAssignmentListStep struct {
	name       string
	moduleName string
}

func newPermitRoleAssignmentListStep(name string, config map[string]any) (*permitRoleAssignmentListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRoleAssignmentListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRoleAssignmentListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("role_assignments"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"role_assignments": result}}, nil
}

// --- step.permit_bulk_assign ---

type permitBulkAssignStep struct {
	name       string
	moduleName string
}

func newPermitBulkAssignStep(name string, config map[string]any) (*permitBulkAssignStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitBulkAssignStep{name: name, moduleName: moduleName}, nil
}

func (s *permitBulkAssignStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	assignments, _ := config["assignments"].([]any)
	if assignments == nil {
		assignments, _ = current["assignments"].([]any)
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("role_assignments/bulk"), assignments)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_bulk_unassign ---

type permitBulkUnassignStep struct {
	name       string
	moduleName string
}

func newPermitBulkUnassignStep(name string, config map[string]any) (*permitBulkUnassignStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitBulkUnassignStep{name: name, moduleName: moduleName}, nil
}

func (s *permitBulkUnassignStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	assignments, _ := config["assignments"].([]any)
	if assignments == nil {
		assignments, _ = current["assignments"].([]any)
	}

	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("role_assignments/bulk"), assignments)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"unassigned": true}}, nil
}
