package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Casbin ReBAC steps use g2 (object grouping) to model relationships.
// The model must define: g2 = _, _
// Relationships are stored as g2 grouping policies.

// --- step.authz_rebac_add_relation ---

type authzReBACAddRelationStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzReBACAddRelationStep(name string, config map[string]any) (*authzReBACAddRelationStep, error) {
	s := &authzReBACAddRelationStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	object, _ := config["object"].(string)
	relation, _ := config["relation"].(string)
	subject, _ := config["subject"].(string)
	if object == "" || relation == "" || subject == "" {
		return nil, fmt.Errorf("step.authz_rebac_add_relation %q: object, relation, and subject are required", name)
	}
	// Store as [subject, relation:object] for g grouping policy
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, relation, object})
	return s, nil
}

func (s *authzReBACAddRelationStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	vals, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_add_relation %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_rebac_add_relation %q: module %q not found", s.name, s.moduleName)
	}

	// Add as a named grouping policy for g2: (subject, relation, object)
	// Using AddNamedGroupingPolicy with "g2" for relationship grouping
	mod.mu.Lock()
	defer mod.mu.Unlock()
	if mod.enforcer == nil {
		return nil, fmt.Errorf("step.authz_rebac_add_relation %q: enforcer not initialized", s.name)
	}

	added, err := mod.enforcer.AddNamedGroupingPolicy("g2", vals[0], vals[1], vals[2])
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_add_relation %q: %w", s.name, err)
	}
	if added && !mod.enforcer.IsFiltered() {
		if err := mod.enforcer.SavePolicy(); err != nil {
			return nil, fmt.Errorf("step.authz_rebac_add_relation %q: save: %w", s.name, err)
		}
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"added":    added,
			"subject":  vals[0],
			"relation": vals[1],
			"object":   vals[2],
		},
	}, nil
}

// --- step.authz_rebac_remove_relation ---

type authzReBACRemoveRelationStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzReBACRemoveRelationStep(name string, config map[string]any) (*authzReBACRemoveRelationStep, error) {
	s := &authzReBACRemoveRelationStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	object, _ := config["object"].(string)
	relation, _ := config["relation"].(string)
	subject, _ := config["subject"].(string)
	if object == "" || relation == "" || subject == "" {
		return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: object, relation, and subject are required", name)
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, relation, object})
	return s, nil
}

func (s *authzReBACRemoveRelationStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	vals, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: module %q not found", s.name, s.moduleName)
	}

	mod.mu.Lock()
	defer mod.mu.Unlock()
	if mod.enforcer == nil {
		return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: enforcer not initialized", s.name)
	}

	removed, err := mod.enforcer.RemoveNamedGroupingPolicy("g2", vals[0], vals[1], vals[2])
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: %w", s.name, err)
	}
	if removed && !mod.enforcer.IsFiltered() {
		if err := mod.enforcer.SavePolicy(); err != nil {
			return nil, fmt.Errorf("step.authz_rebac_remove_relation %q: save: %w", s.name, err)
		}
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"removed":  removed,
			"subject":  vals[0],
			"relation": vals[1],
			"object":   vals[2],
		},
	}, nil
}

// --- step.authz_rebac_check ---

type authzReBACCheckStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzReBACCheckStep(name string, config map[string]any) (*authzReBACCheckStep, error) {
	s := &authzReBACCheckStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	subject, _ := config["subject"].(string)
	object, _ := config["object"].(string)
	action, _ := config["action"].(string)
	if subject == "" || object == "" || action == "" {
		return nil, fmt.Errorf("step.authz_rebac_check %q: subject, object, and action are required", name)
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, object, action})
	return s, nil
}

func (s *authzReBACCheckStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	vals, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_check %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_rebac_check %q: module %q not found", s.name, s.moduleName)
	}

	allowed, err := mod.Enforce(vals[0], vals[1], vals[2])
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_check %q: enforce: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"allowed": allowed,
			"subject": vals[0],
			"object":  vals[1],
			"action":  vals[2],
		},
	}, nil
}

// --- step.authz_rebac_list_relations ---

type authzReBACListRelationsStep struct {
	name       string
	moduleName string
	filter     string // "subject" or "object"
	value      string
	valueTmpl  *template.Template
	registry   moduleRegistry
}

func newAuthzReBACListRelationsStep(name string, config map[string]any) (*authzReBACListRelationsStep, error) {
	s := &authzReBACListRelationsStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}

	filter, _ := config["filter"].(string)
	if filter == "" {
		filter = "subject"
	}
	if filter != "subject" && filter != "object" {
		return nil, fmt.Errorf("step.authz_rebac_list_relations %q: filter must be \"subject\" or \"object\"", name)
	}
	s.filter = filter

	value, _ := config["value"].(string)
	if value == "" {
		return nil, fmt.Errorf("step.authz_rebac_list_relations %q: value is required", name)
	}
	if isTemplate(value) {
		t, err := template.New("value").Parse(value)
		if err != nil {
			return nil, fmt.Errorf("step.authz_rebac_list_relations %q: parse value template: %w", name, err)
		}
		s.valueTmpl = t
	} else {
		s.value = value
	}

	return s, nil
}

func (s *authzReBACListRelationsStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	value, err := resolve(s.value, s.valueTmpl, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_rebac_list_relations %q: resolve value: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_rebac_list_relations %q: module %q not found", s.name, s.moduleName)
	}

	mod.mu.RLock()
	e := mod.enforcer
	mod.mu.RUnlock()
	if e == nil {
		return nil, fmt.Errorf("step.authz_rebac_list_relations %q: enforcer not initialized", s.name)
	}

	relations, _ := e.GetNamedGroupingPolicy("g2")
	var entries []map[string]any
	for _, r := range relations {
		if len(r) < 3 {
			continue
		}
		match := false
		switch s.filter {
		case "subject":
			match = r[0] == value
		case "object":
			match = r[2] == value
		}
		if match {
			entries = append(entries, map[string]any{
				"subject":  r[0],
				"relation": r[1],
				"object":   r[2],
			})
		}
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"relations": entries,
			"count":     len(entries),
			"filter":    s.filter,
			"value":     value,
		},
	}, nil
}
