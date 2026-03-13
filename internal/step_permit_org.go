package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_org_get ---

type permitOrgGetStep struct {
	name       string
	moduleName string
}

func newPermitOrgGetStep(name string, config map[string]any) (*permitOrgGetStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitOrgGetStep{name: name, moduleName: moduleName}, nil
}

func (s *permitOrgGetStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPI(ctx, http.MethodGet, "/v2/orgs/me", nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_org_update ---

type permitOrgUpdateStep struct {
	name       string
	moduleName string
}

func newPermitOrgUpdateStep(name string, config map[string]any) (*permitOrgUpdateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitOrgUpdateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitOrgUpdateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"name"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPatch, "/v2/orgs/me", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_org_member_list ---

type permitOrgMemberListStep struct {
	name       string
	moduleName string
}

func newPermitOrgMemberListStep(name string, config map[string]any) (*permitOrgMemberListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitOrgMemberListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitOrgMemberListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, "/v2/members", nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"members": result}}, nil
}

// --- step.permit_org_member_invite ---

type permitOrgMemberInviteStep struct {
	name       string
	moduleName string
}

func newPermitOrgMemberInviteStep(name string, config map[string]any) (*permitOrgMemberInviteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitOrgMemberInviteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitOrgMemberInviteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"email", "role"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, "/v2/members", body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_org_member_remove ---

type permitOrgMemberRemoveStep struct {
	name       string
	moduleName string
}

func newPermitOrgMemberRemoveStep(name string, config map[string]any) (*permitOrgMemberRemoveStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitOrgMemberRemoveStep{name: name, moduleName: moduleName}, nil
}

func (s *permitOrgMemberRemoveStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	memberID := resolvePermitValue("member_id", current, config)
	_, err := client.doAPI(ctx, http.MethodDelete, "/v2/members/"+memberID, nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"removed": true, "member_id": memberID}}, nil
}
