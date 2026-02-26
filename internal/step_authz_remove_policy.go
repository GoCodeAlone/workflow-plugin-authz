package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// authzRemovePolicyStep implements sdk.StepInstance. It removes a policy rule
// from the Casbin enforcer at runtime.
//
// Config:
//
//	module: "authz"                    # name of the authz.casbin module (default: "authz")
//	rule: ["admin", "/api/*", "*"]     # policy rule; each element may be a Go template
type authzRemovePolicyStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template
	ruleStatic []string
	registry   moduleRegistry
}

func newAuthzRemovePolicyStep(name string, config map[string]any) (*authzRemovePolicyStep, error) {
	s := &authzRemovePolicyStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}

	rule, err := parseRuleConfig(name, "step.authz_remove_policy", config)
	if err != nil {
		return nil, err
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates(rule)
	return s, nil
}

// Execute removes the policy rule from the enforcer.
func (s *authzRemovePolicyStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)

	rule, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_remove_policy %q: resolve rule: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_remove_policy %q: authz module %q not found", s.name, s.moduleName)
	}

	removed, err := mod.RemovePolicy(rule)
	if err != nil {
		return nil, fmt.Errorf("step.authz_remove_policy %q: remove policy: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"authz_policy_removed": removed,
			"authz_rule":           rule,
		},
	}, nil
}
