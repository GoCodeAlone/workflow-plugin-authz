package internal

import (
	"context"
	"net/http"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.permit_relationship_tuple_create ---

type permitRelationshipTupleCreateStep struct {
	name       string
	moduleName string
}

func newPermitRelationshipTupleCreateStep(name string, config map[string]any) (*permitRelationshipTupleCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRelationshipTupleCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRelationshipTupleCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"subject", "relation", "object", "tenant"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("relationship_tuples"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_relationship_tuple_delete ---

type permitRelationshipTupleDeleteStep struct {
	name       string
	moduleName string
}

func newPermitRelationshipTupleDeleteStep(name string, config map[string]any) (*permitRelationshipTupleDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRelationshipTupleDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRelationshipTupleDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	body := map[string]any{}
	for _, k := range []string{"subject", "relation", "object", "tenant"} {
		if v := resolvePermitValue(k, current, config); v != "" {
			body[k] = v
		}
	}

	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("relationship_tuples"), body)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true}}, nil
}

// --- step.permit_relationship_tuple_list ---

type permitRelationshipTupleListStep struct {
	name       string
	moduleName string
}

func newPermitRelationshipTupleListStep(name string, config map[string]any) (*permitRelationshipTupleListStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRelationshipTupleListStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRelationshipTupleListStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, _ map[string]any, _ map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	result, err := client.doAPIList(ctx, http.MethodGet, client.permitFactsPath("relationship_tuples"), nil)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"relationship_tuples": result}}, nil
}

// --- step.permit_relationship_tuple_bulk_create ---

type permitRelationshipTupleBulkCreateStep struct {
	name       string
	moduleName string
}

func newPermitRelationshipTupleBulkCreateStep(name string, config map[string]any) (*permitRelationshipTupleBulkCreateStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRelationshipTupleBulkCreateStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRelationshipTupleBulkCreateStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tuples, _ := config["tuples"].([]any)
	if tuples == nil {
		tuples, _ = current["tuples"].([]any)
	}

	result, err := client.doAPI(ctx, http.MethodPost, client.permitFactsPath("relationship_tuples/bulk"), tuples)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: result}, nil
}

// --- step.permit_relationship_tuple_bulk_delete ---

type permitRelationshipTupleBulkDeleteStep struct {
	name       string
	moduleName string
}

func newPermitRelationshipTupleBulkDeleteStep(name string, config map[string]any) (*permitRelationshipTupleBulkDeleteStep, error) {
	moduleName := "permit"
	if v, ok := config["module"].(string); ok && v != "" {
		moduleName = v
	}
	return &permitRelationshipTupleBulkDeleteStep{name: name, moduleName: moduleName}, nil
}

func (s *permitRelationshipTupleBulkDeleteStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetPermitClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "permit client not found: " + s.moduleName}}, nil
	}

	tuples, _ := config["tuples"].([]any)
	if tuples == nil {
		tuples, _ = current["tuples"].([]any)
	}

	_, err := client.doAPI(ctx, http.MethodDelete, client.permitFactsPath("relationship_tuples/bulk"), tuples)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": err.Error()}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{"deleted": true}}, nil
}
