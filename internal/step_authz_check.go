package internal

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// authzCheckStep implements sdk.StepInstance. It looks up the Casbin enforcer
// registered under a named module and checks whether the authenticated user
// has permission to perform the configured action on the configured object.
//
// Config:
//
//	module: "authz"            # name of the authz.casbin module (default: "authz")
//	subject_key: "auth_user_id" # step output key carrying the subject (default: "auth_user_id")
//	object: "/api/v1/tenants"  # static object, or Go template: "{{.request_path}}"
//	action: "POST"             # static action, or Go template: "{{.request_method}}"
type authzCheckStep struct {
	name       string
	moduleName string
	subjectKey string
	object     string
	action     string

	// parsed templates (nil when static string is used)
	objectTmpl *template.Template
	actionTmpl *template.Template

	// registry is injected during CreateStep so tests can wire a mock module.
	registry moduleRegistry
}

// moduleRegistry abstracts module look-up so tests can inject a fake enforcer.
type moduleRegistry interface {
	// GetEnforcer returns the CasbinModule for the given module name.
	GetEnforcer(name string) (*CasbinModule, bool)
}

// globalRegistry is the package-level registry shared between all steps created
// by CreateModule. It maps module-name → *CasbinModule.
var globalRegistry = &defaultRegistry{
	modules: make(map[string]*CasbinModule),
}

// RegisterModule adds a CasbinModule to the global registry. It is called by
// CreateModule so that CreateStep can find the enforcer by name.
func RegisterModule(m *CasbinModule) {
	globalRegistry.set(m.name, m)
}

// defaultRegistry is a simple thread-safe module registry backed by a map.
type defaultRegistry struct {
	modules map[string]*CasbinModule
}

func (r *defaultRegistry) set(name string, m *CasbinModule) {
	r.modules[name] = m
}

func (r *defaultRegistry) GetEnforcer(name string) (*CasbinModule, bool) {
	m, ok := r.modules[name]
	return m, ok
}

// newAuthzCheckStep parses step config and returns an authzCheckStep.
func newAuthzCheckStep(name string, config map[string]any) (*authzCheckStep, error) {
	s := &authzCheckStep{
		name:       name,
		moduleName: "authz",
		subjectKey: "auth_user_id",
		registry:   globalRegistry,
	}

	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	if v, ok := config["subject_key"].(string); ok && v != "" {
		s.subjectKey = v
	}

	object, _ := config["object"].(string)
	action, _ := config["action"].(string)

	if object == "" {
		return nil, fmt.Errorf("step.authz_check %q: config.object is required", name)
	}
	if action == "" {
		return nil, fmt.Errorf("step.authz_check %q: config.action is required", name)
	}

	// Compile as Go template if it looks like one.
	var err error
	if isTemplate(object) {
		s.objectTmpl, err = template.New("object").Parse(object)
		if err != nil {
			return nil, fmt.Errorf("step.authz_check %q: parse object template: %w", name, err)
		}
	} else {
		s.object = object
	}

	if isTemplate(action) {
		s.actionTmpl, err = template.New("action").Parse(action)
		if err != nil {
			return nil, fmt.Errorf("step.authz_check %q: parse action template: %w", name, err)
		}
	} else {
		s.action = action
	}

	return s, nil
}

// isTemplate reports whether s contains a Go template expression.
func isTemplate(s string) bool {
	return strings.Contains(s, "{{") && strings.Contains(s, "}}")
}

// Execute checks whether the authenticated user has the required permission.
// It reads the subject from step outputs (keyed by s.subjectKey), resolves the
// object and action (from config or templates), and enforces via Casbin.
// Returns a 403 StepResult with StopPipeline=true when access is denied.
func (s *authzCheckStep) Execute(
	_ context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	// Resolve subject: search step outputs then current for the subject key.
	subject := resolveSubject(s.subjectKey, stepOutputs, current, triggerData)
	if subject == "" {
		return forbiddenResult("missing authentication subject; ensure step.auth_required runs first"), nil
	}

	// Build template data from all available context.
	tmplData := buildTemplateData(triggerData, stepOutputs, current)

	object, err := resolve(s.object, s.objectTmpl, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: resolve object: %w", s.name, err)
	}

	action, err := resolve(s.action, s.actionTmpl, tmplData)
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: resolve action: %w", s.name, err)
	}

	// Look up the Casbin enforcer.
	mod, ok := s.registry.GetEnforcer(s.moduleName)
	if !ok {
		return nil, fmt.Errorf("step.authz_check %q: authz module %q not found; check module name in config", s.name, s.moduleName)
	}

	allowed, err := mod.Enforce(subject, object, action)
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: enforce: %w", s.name, err)
	}

	if !allowed {
		return forbiddenResult(fmt.Sprintf("forbidden: %s is not permitted to %s %s", subject, action, object)), nil
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"authz_subject": subject,
			"authz_object":  object,
			"authz_action":  action,
			"authz_allowed": true,
		},
	}, nil
}

// forbiddenResult returns a StepResult that stops the pipeline with a 403 body.
func forbiddenResult(msg string) *sdk.StepResult {
	return &sdk.StepResult{
		StopPipeline: true,
		Output: map[string]any{
			"response_status":  403,
			"response_body":    fmt.Sprintf(`{"error":%q}`, msg),
			"response_headers": map[string]any{"Content-Type": "application/json"},
			"authz_allowed":    false,
		},
	}
}

// resolveSubject searches for subjectKey in (in order):
// 1. Each prior step's output map.
// 2. current (merged pipeline context).
// 3. triggerData.
func resolveSubject(key string, stepOutputs map[string]map[string]any, current, triggerData map[string]any) string {
	for _, out := range stepOutputs {
		if v, ok := out[key].(string); ok && v != "" {
			return v
		}
	}
	if v, ok := current[key].(string); ok && v != "" {
		return v
	}
	if v, ok := triggerData[key].(string); ok && v != "" {
		return v
	}
	return ""
}

// buildTemplateData merges all context maps into a single flat map for template
// execution. Later sources overwrite earlier ones: triggerData < stepOutputs < current.
func buildTemplateData(triggerData map[string]any, stepOutputs map[string]map[string]any, current map[string]any) map[string]any {
	data := make(map[string]any)
	for k, v := range triggerData {
		data[k] = v
	}
	for _, out := range stepOutputs {
		for k, v := range out {
			data[k] = v
		}
	}
	for k, v := range current {
		data[k] = v
	}
	return data
}

// resolve returns staticVal when no template is set; otherwise it executes tmpl
// against data and returns the rendered string.
func resolve(staticVal string, tmpl *template.Template, data map[string]any) (string, error) {
	if tmpl == nil {
		return staticVal, nil
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
