package internal

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// authzAddPolicyStep implements sdk.StepInstance. It adds a policy rule to the
// Casbin enforcer at runtime and persists it via the adapter's SavePolicy.
//
// Config:
//
//	module: "authz"                    # name of the authz.casbin module (default: "authz")
//	rule: ["admin", "/api/*", "*"]     # policy rule; each element may be a Go template
type authzAddPolicyStep struct {
	name       string
	moduleName string
	ruleTmpls  []*template.Template // one per rule element; nil entry = static string
	ruleStatic []string             // static value for the corresponding index (when tmpl is nil)
	registry   moduleRegistry
}

func newAuthzAddPolicyStep(name string, config map[string]any) (*authzAddPolicyStep, error) {
	s := &authzAddPolicyStep{
		name:       name,
		moduleName: "authz",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}

	rule, err := parseRuleConfig(name, "step.authz_add_policy", config)
	if err != nil {
		return nil, err
	}
	s.ruleStatic, s.ruleTmpls = compileRuleTemplates(rule)
	return s, nil
}

// Execute adds the policy rule to the enforcer.
func (s *authzAddPolicyStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)

	rule, err := resolveRule(s.ruleStatic, s.ruleTmpls, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_add_policy %q: resolve rule: %w", s.name, err)
	}

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_add_policy %q: authz module %q not found", s.name, s.moduleName)
	}

	added, err := mod.AddPolicy(rule)
	if err != nil {
		return nil, fmt.Errorf("step.authz_add_policy %q: add policy: %w", s.name, err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"authz_policy_added": added,
			"authz_rule":         rule,
		},
	}, nil
}

// --- helpers shared by add/remove/role steps ---

// parseRuleConfig extracts the "rule" field from config as []string.
func parseRuleConfig(stepName, stepType string, config map[string]any) ([]string, error) {
	ruleAny, ok := config["rule"]
	if !ok {
		return nil, fmt.Errorf("%s %q: config.rule is required", stepType, stepName)
	}
	rule, err := toStringSlice(ruleAny)
	if err != nil {
		return nil, fmt.Errorf("%s %q: config.rule: %w", stepType, stepName, err)
	}
	if len(rule) == 0 {
		return nil, fmt.Errorf("%s %q: config.rule must not be empty", stepType, stepName)
	}
	return rule, nil
}

// compileRuleTemplates returns parallel slices: static strings and compiled templates.
// For each element, exactly one of static[i] or tmpls[i] is meaningful.
func compileRuleTemplates(rule []string) (static []string, tmpls []*template.Template) {
	static = make([]string, len(rule))
	tmpls = make([]*template.Template, len(rule))
	for i, elem := range rule {
		if isTemplate(elem) {
			t, err := template.New(fmt.Sprintf("rule[%d]", i)).Parse(elem)
			if err == nil {
				tmpls[i] = t
			} else {
				static[i] = elem // fall back to static on parse error
			}
		} else {
			static[i] = elem
		}
	}
	return static, tmpls
}

// resolveRule evaluates templates against data and returns the resolved rule.
func resolveRule(static []string, tmpls []*template.Template, data map[string]any) ([]string, error) {
	out := make([]string, len(static))
	for i := range static {
		if tmpls[i] != nil {
			var buf bytes.Buffer
			if err := tmpls[i].Execute(&buf, data); err != nil {
				return nil, fmt.Errorf("rule[%d]: %w", i, err)
			}
			out[i] = buf.String()
		} else {
			out[i] = static[i]
		}
	}
	return out, nil
}
