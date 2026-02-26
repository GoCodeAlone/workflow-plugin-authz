package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// authzRoleAssignStep implements sdk.StepInstance. It adds or removes a role
// mapping (grouping policy) in the Casbin enforcer at runtime.
//
// Config:
//
//	module: "authz"          # name of the authz.casbin module (default: "authz")
//	action: "add"            # "add" (default) or "remove"
//	assignments:             # list of [user, role] pairs; values may be Go templates
//	  - ["{{.user}}", "admin"]
type authzRoleAssignStep struct {
	name        string
	moduleName  string
	action      string // "add" or "remove"
	assignments []roleAssignment
	registry    moduleRegistry
}

// roleAssignment holds the compiled template data for a single [user, role] pair.
type roleAssignment struct {
	static []string
	tmpls  []*template.Template
}

func newAuthzRoleAssignStep(name string, config map[string]any) (*authzRoleAssignStep, error) {
	s := &authzRoleAssignStep{
		name:       name,
		moduleName: "authz",
		action:     "add",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	if v, ok := config["action"].(string); ok && v != "" {
		switch v {
		case "add", "remove":
			s.action = v
		default:
			return nil, fmt.Errorf("step.authz_role_assign %q: action must be \"add\" or \"remove\", got %q", name, v)
		}
	}

	rawAssignments, ok := config["assignments"].([]any)
	if !ok || len(rawAssignments) == 0 {
		return nil, fmt.Errorf("step.authz_role_assign %q: config.assignments is required", name)
	}

	for i, a := range rawAssignments {
		row, err := toStringSlice(a)
		if err != nil {
			return nil, fmt.Errorf("step.authz_role_assign %q: assignments[%d]: %w", name, i, err)
		}
		if len(row) < 2 {
			return nil, fmt.Errorf("step.authz_role_assign %q: assignments[%d]: expected [user, role], got %v", name, i, row)
		}
		st, tmpls := compileRuleTemplates(row)
		s.assignments = append(s.assignments, roleAssignment{static: st, tmpls: tmpls})
	}

	return s, nil
}

// Execute adds or removes role mappings in the enforcer.
func (s *authzRoleAssignStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	tmplData := buildTemplateData(triggerData, stepOutputs, current)

	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_role_assign %q: authz module %q not found", s.name, s.moduleName)
	}

	var processed [][]string
	for i, a := range s.assignments {
		rule, err := resolveRule(a.static, a.tmpls, tmplData)
		if err != nil {
			return nil, fmt.Errorf("step.authz_role_assign %q: resolve assignments[%d]: %w", s.name, i, err)
		}

		var opErr error
		switch s.action {
		case "add":
			_, opErr = mod.AddGroupingPolicy(rule)
		case "remove":
			_, opErr = mod.RemoveGroupingPolicy(rule)
		}
		if opErr != nil {
			return nil, fmt.Errorf("step.authz_role_assign %q: %s assignment[%d]: %w", s.name, s.action, i, opErr)
		}
		processed = append(processed, rule)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"authz_role_action":      s.action,
			"authz_role_assignments": processed,
		},
	}, nil
}
