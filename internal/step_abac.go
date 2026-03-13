package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- step.authz_abac_check ---

// authzABACCheckStep checks authorization using attribute-based conditions.
// The Casbin model must be configured with ABAC matchers that reference
// request attributes (e.g., r.sub_attrs.department == p.sub_attrs).
//
// Config:
//
//	module: "authz"                  # name of the authz.casbin module
//	subject: "alice"                 # subject identifier (may be template)
//	object: "document"              # object identifier (may be template)
//	action: "read"                  # action (may be template)
//	subject_attrs:                  # subject attributes passed to Casbin
//	  department: "engineering"
//	object_attrs:                   # object attributes passed to Casbin
//	  type: "code"
type authzABACCheckStep struct {
	name          string
	moduleName    string
	subjectTmpls  []*template.Template
	subjectStatic []string
	registry      moduleRegistry
}

func newAuthzABACCheckStep(name string, config map[string]any) (*authzABACCheckStep, error) {
	s := &authzABACCheckStep{
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
		return nil, fmt.Errorf("step.authz_abac_check %q: subject, object, and action are required", name)
	}
	s.subjectStatic, s.subjectTmpls = compileRuleTemplates([]string{subject, object, action})
	return s, nil
}

func (s *authzABACCheckStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)
	vals, err := resolveRule(s.subjectStatic, s.subjectTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_abac_check %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_abac_check %q: module %q not found", s.name, s.moduleName)
	}

	allowed, err := mod.Enforce(vals[0], vals[1], vals[2])
	if err != nil {
		return nil, fmt.Errorf("step.authz_abac_check %q: enforce: %w", s.name, err)
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

// --- step.authz_abac_add_policy ---

// authzABACAddPolicyStep adds an attribute-based policy rule to Casbin.
type authzABACAddPolicyStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzABACAddPolicyStep(name string, config map[string]any) (*authzABACAddPolicyStep, error) {
	s := &authzABACAddPolicyStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	rule, err := parseRuleConfig(name, "step.authz_abac_add_policy", config)
	if err != nil {
		return nil, err
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates(rule)
	return s, nil
}

func (s *authzABACAddPolicyStep) Execute(
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
		return nil, fmt.Errorf("step.authz_abac_add_policy %q: resolve: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_abac_add_policy %q: module %q not found", s.name, s.moduleName)
	}

	added, err := mod.AddPolicy(rule)
	if err != nil {
		return nil, fmt.Errorf("step.authz_abac_add_policy %q: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"policy_added": added,
			"rule":         rule,
		},
	}, nil
}
