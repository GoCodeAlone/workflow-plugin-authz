package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.authz_acl_grant ---

// authzACLGrantStep grants access (subject, object, action) via Casbin AddPolicy.
type authzACLGrantStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzACLGrantStep(name string, config map[string]any) (*authzACLGrantStep, error) {
	s := &authzACLGrantStep{
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
		return nil, fmt.Errorf("step.authz_acl_grant %q: subject, object, and action are required", name)
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, object, action})
	return s, nil
}

func (s *authzACLGrantStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	rule, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_grant %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_acl_grant %q: module %q not found", s.name, s.moduleName)
	}

	added, err := mod.AddPolicy(rule)
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_grant %q: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"granted": added,
			"subject": rule[0],
			"object":  rule[1],
			"action":  rule[2],
		},
	}, nil
}

// --- step.authz_acl_revoke ---

type authzACLRevokeStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzACLRevokeStep(name string, config map[string]any) (*authzACLRevokeStep, error) {
	s := &authzACLRevokeStep{
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
		return nil, fmt.Errorf("step.authz_acl_revoke %q: subject, object, and action are required", name)
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, object, action})
	return s, nil
}

func (s *authzACLRevokeStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	rule, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_revoke %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_acl_revoke %q: module %q not found", s.name, s.moduleName)
	}

	removed, err := mod.RemovePolicy(rule)
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_revoke %q: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"revoked": removed,
			"subject": rule[0],
			"object":  rule[1],
			"action":  rule[2],
		},
	}, nil
}

// --- step.authz_acl_check ---

type authzACLCheckStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzACLCheckStep(name string, config map[string]any) (*authzACLCheckStep, error) {
	s := &authzACLCheckStep{
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
		return nil, fmt.Errorf("step.authz_acl_check %q: subject, object, and action are required", name)
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates([]string{subject, object, action})
	return s, nil
}

func (s *authzACLCheckStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	rule, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_check %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_acl_check %q: module %q not found", s.name, s.moduleName)
	}

	allowed, err := mod.Enforce(rule[0], rule[1], rule[2])
	if err != nil {
		return nil, fmt.Errorf("step.authz_acl_check %q: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"allowed": allowed,
			"subject": rule[0],
			"object":  rule[1],
			"action":  rule[2],
		},
	}, nil
}

// --- step.authz_acl_list ---

// authzACLListStep lists ACL entries for a subject or object.
type authzACLListStep struct {
	name       string
	moduleName string
	filter     string // "subject" or "object"
	value      string
	valueTmpl  *template.Template
	registry   moduleRegistry
}

func newAuthzACLListStep(name string, config map[string]any) (*authzACLListStep, error) {
	s := &authzACLListStep{
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
		return nil, fmt.Errorf("step.authz_acl_list %q: filter must be \"subject\" or \"object\"", name)
	}
	s.filter = filter

	value, _ := config["value"].(string)
	if value == "" {
		return nil, fmt.Errorf("step.authz_acl_list %q: value is required", name)
	}
	if isTemplate(value) {
		t, err := template.New("value").Parse(value)
		if err != nil {
			return nil, fmt.Errorf("step.authz_acl_list %q: parse value template: %w", name, err)
		}
		s.valueTmpl = t
	} else {
		s.value = value
	}

	return s, nil
}

func (s *authzACLListStep) Execute(
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
		return nil, fmt.Errorf("step.authz_acl_list %q: resolve value: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_acl_list %q: module %q not found", s.name, s.moduleName)
	}

	mod.mu.RLock()
	e := mod.enforcer
	mod.mu.RUnlock()
	if e == nil {
		return nil, fmt.Errorf("step.authz_acl_list %q: enforcer not initialized", s.name)
	}

	policies, _ := e.GetPolicy()
	var entries []map[string]any
	for _, p := range policies {
		if len(p) < 3 {
			continue
		}
		match := false
		switch s.filter {
		case "subject":
			match = p[0] == value
		case "object":
			match = p[1] == value
		}
		if match {
			entries = append(entries, map[string]any{
				"subject": p[0],
				"object":  p[1],
				"action":  p[2],
			})
		}
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"entries": entries,
			"count":   len(entries),
			"filter":  s.filter,
			"value":   value,
		},
	}, nil
}
