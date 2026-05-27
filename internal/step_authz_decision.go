package internal

import (
	"context"
	"fmt"
	"text/template"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authzDecisionStep struct {
	name             string
	moduleName       string
	provider         string
	mode             AuthzCapability
	static           []string
	tmpls            []*template.Template
	subjectAttrs     map[string]string
	resourceAttrs    map[string]string
	environmentAttrs map[string]string
	registry         moduleRegistry
}

func newAuthzDecisionStep(name string, config map[string]any) (*authzDecisionStep, error) {
	step := &authzDecisionStep{name: name, moduleName: "authz", provider: "casbin", registry: globalRegistry}
	if v := stringValue(config["module"]); v != "" {
		step.moduleName = v
	}
	if v := stringValue(config["provider"]); v != "" {
		step.provider = v
	}
	step.mode = AuthzCapability(stringValue(config["mode"]))
	step.static, step.tmpls = compileRuleTemplates([]string{
		stringValue(config["subject"]),
		stringValue(config["context"]),
		stringValue(config["resource"]),
		stringValue(config["action"]),
		stringValue(config["scope"]),
		stringValue(config["relation"]),
	})
	step.subjectAttrs = stringMapFromAny(config["subject_attributes"])
	step.resourceAttrs = stringMapFromAny(config["resource_attributes"])
	step.environmentAttrs = stringMapFromAny(config["environment_attributes"])
	return step, nil
}

func (s *authzDecisionStep) Execute(
	ctx context.Context,
	triggerData map[string]any,
	stepOutputs map[string]map[string]any,
	current map[string]any,
	metadata map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	values, err := resolveRule(s.static, s.tmpls, buildTemplateData(triggerData, stepOutputs, current))
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: resolve: %w", s.name, err)
	}
	provider, err := resolveDecisionProvider(s.registry, s.moduleName, s.provider)
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: %w", s.name, err)
	}
	decision, err := DecideAuthorization(ctx, provider, AuthorizationDecisionInput{
		Provider:              s.provider,
		Mode:                  s.mode,
		Subject:               values[0],
		Context:               values[1],
		Resource:              values[2],
		Action:                values[3],
		Scope:                 values[4],
		Relation:              values[5],
		SubjectAttributes:     s.subjectAttrs,
		ResourceAttributes:    s.resourceAttrs,
		EnvironmentAttributes: s.environmentAttrs,
		Explain:               boolValue(metadata["explain"]),
	})
	if err != nil {
		return nil, fmt.Errorf("step.authz_check %q: %w", s.name, err)
	}
	return &sdk.StepResult{Output: authorizationDecisionOutputToMap(decision)}, nil
}

type authzRequireCapabilitiesStep struct {
	name         string
	moduleName   string
	provider     string
	requirements []CapabilityRequirement
	registry     moduleRegistry
}

func newAuthzRequireCapabilitiesStep(name string, config map[string]any) (*authzRequireCapabilitiesStep, error) {
	step := &authzRequireCapabilitiesStep{name: name, moduleName: "authz", provider: "casbin", registry: globalRegistry}
	if v := stringValue(config["module"]); v != "" {
		step.moduleName = v
	}
	if v := stringValue(config["provider"]); v != "" {
		step.provider = v
	}
	step.requirements = capabilityRequirementsFromAny(config["requirements"])
	return step, nil
}

func (s *authzRequireCapabilitiesStep) Execute(
	ctx context.Context,
	_ map[string]any,
	_ map[string]map[string]any,
	_ map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	_ = ctx
	provider, err := resolveDecisionProvider(s.registry, s.moduleName, s.provider)
	if err != nil {
		return nil, fmt.Errorf("step.authz_require_capabilities %q: %w", s.name, err)
	}
	authzProvider, ok := provider.(AuthzProvider)
	if !ok {
		return nil, fmt.Errorf("step.authz_require_capabilities %q: provider does not expose capabilities", s.name)
	}
	out := providerCapabilitiesOutputMap(s.moduleName, s.provider, authzProvider, s.requirements)
	if err := authzProvider.RequireCapabilities(s.requirements); err != nil {
		return &sdk.StepResult{Output: out}, err
	}
	return &sdk.StepResult{Output: out}, nil
}

func resolveDecisionProvider(registry moduleRegistry, moduleName, providerName string) (any, error) {
	switch providerName {
	case "casbin":
		mod, ok := registry.GetEnforcer(moduleName)
		if !ok {
			return nil, fmt.Errorf("casbin module %q not found", moduleName)
		}
		return mod, nil
	case "permit", "keto":
		reg, ok := registry.(authzProviderRegistry)
		if !ok {
			return nil, fmt.Errorf("registry cannot look up %s module %q", providerName, moduleName)
		}
		provider, ok := reg.GetAuthzProvider(moduleName)
		if !ok {
			return nil, fmt.Errorf("%s module %q not found", providerName, moduleName)
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unknown provider %q", providerName)
	}
}

func authorizationDecisionOutputToMap(decision AuthorizationDecisionOutput) map[string]any {
	return compactMap(map[string]any{
		"allowed": decision.Allowed,
		"mode":    string(decision.Mode),
		"subject": decision.Subject,
		"context": decision.Context,
		"reason":  decision.Reason,
		"explain": decision.Explain,
	})
}
