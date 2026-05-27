package internal

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// AuthzCapability represents an authorization model supported by a provider.
type AuthzCapability string

const (
	CapabilityRBAC  AuthzCapability = "rbac"  // Role-Based Access Control
	CapabilityABAC  AuthzCapability = "abac"  // Attribute-Based Access Control
	CapabilityReBAC AuthzCapability = "rebac" // Relationship-Based Access Control
	CapabilityACL   AuthzCapability = "acl"   // Access Control Lists
)

// AuthzProvider is implemented by authorization providers to declare their
// supported authorization models.
type AuthzProvider interface {
	Capabilities() []AuthzCapability
	SupportsCapability(AuthzCapability) bool
}

// Capabilities returns the authorization models supported by Casbin.
func (m *CasbinModule) Capabilities() []AuthzCapability {
	modelText := strings.ToLower(m.config.Model)
	capabilities := make([]AuthzCapability, 0, 4)
	if casbinModelHasRoleDefinition(modelText, "g") {
		capabilities = append(capabilities, CapabilityRBAC)
	}
	if casbinModelHasRoleDefinition(modelText, "g2") || strings.Contains(modelText, "g2(") {
		capabilities = append(capabilities, CapabilityReBAC)
	}
	if casbinModelHasAttributeAccess(modelText) {
		capabilities = append(capabilities, CapabilityABAC)
	}
	if len(capabilities) == 0 {
		capabilities = append(capabilities, CapabilityACL)
	}
	return capabilities
}

// SupportsCapability reports whether the Casbin module supports the given
// authorization model.
func (m *CasbinModule) SupportsCapability(cap AuthzCapability) bool {
	for _, c := range m.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// Capabilities returns the authorization models supported by Permit.io.
func (m *PermitModule) Capabilities() []AuthzCapability {
	return []AuthzCapability{CapabilityRBAC, CapabilityABAC, CapabilityReBAC}
}

// SupportsCapability reports whether the Permit module supports the given
// authorization model.
func (m *PermitModule) SupportsCapability(cap AuthzCapability) bool {
	for _, c := range m.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// Capabilities returns authorization models represented by the Keto adapter.
func (m *KetoModule) Capabilities() []AuthzCapability {
	return []AuthzCapability{CapabilityRBAC, CapabilityReBAC}
}

// SupportsCapability reports whether the Keto module supports the given
// authorization model.
func (m *KetoModule) SupportsCapability(cap AuthzCapability) bool {
	for _, c := range m.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// authzCapabilitiesStep implements sdk.StepInstance. It returns the capabilities
// of a given provider module.
//
// Config:
//
//	module: "authz"    # name of the authz.casbin or permit.provider module
//	provider: "casbin" # "casbin" or "permit" (default: "casbin")
type authzCapabilitiesStep struct {
	name       string
	moduleName string
	provider   string
	registry   moduleRegistry
}

func newAuthzCapabilitiesStep(name string, config map[string]any) (*authzCapabilitiesStep, error) {
	s := &authzCapabilitiesStep{
		name:       name,
		moduleName: "authz",
		provider:   "casbin",
		registry:   globalRegistry,
	}
	if v, ok := config["module"].(string); ok && v != "" {
		s.moduleName = v
	}
	if v, ok := config["provider"].(string); ok && v != "" {
		s.provider = v
	}
	return s, nil
}

// Execute returns the capabilities of the configured provider.
func (s *authzCapabilitiesStep) Execute(
	_ context.Context,
	_ map[string]any,
	_ map[string]map[string]any,
	_ map[string]any,
	_ map[string]any,
	_ map[string]any,
) (*sdk.StepResult, error) {
	var provider AuthzProvider

	switch s.provider {
	case "casbin":
		mod, ok := s.registry.GetEnforcer(s.moduleName)
		if !ok {
			return nil, fmt.Errorf("step.authz_capabilities %q: casbin module %q not found", s.name, s.moduleName)
		}
		provider = mod
	case "permit":
		if reg, ok := s.registry.(authzProviderRegistry); ok {
			if registered, found := reg.GetAuthzProvider(s.moduleName); found {
				provider = registered
				break
			}
		}
		if _, ok := GetPermitClient(s.moduleName); !ok {
			return nil, fmt.Errorf("step.authz_capabilities %q: permit module %q not found", s.name, s.moduleName)
		}
		provider = &PermitModule{name: s.moduleName}
	case "keto":
		reg, ok := s.registry.(authzProviderRegistry)
		if !ok {
			return nil, fmt.Errorf("step.authz_capabilities %q: registry cannot look up keto module %q", s.name, s.moduleName)
		}
		registered, found := reg.GetAuthzProvider(s.moduleName)
		if !found {
			return nil, fmt.Errorf("step.authz_capabilities %q: keto module %q not found", s.name, s.moduleName)
		}
		provider = registered
	default:
		return nil, fmt.Errorf("step.authz_capabilities %q: unknown provider %q (expected \"casbin\", \"permit\", or \"keto\")", s.name, s.provider)
	}

	caps := provider.Capabilities()
	capStrings := make([]any, len(caps))
	for i, c := range caps {
		capStrings[i] = string(c)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"provider":     s.provider,
			"module":       s.moduleName,
			"capabilities": capStrings,
		},
	}, nil
}

func casbinModelHasRoleDefinition(modelText, name string) bool {
	for _, line := range strings.Split(modelText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, name+" ") || strings.HasPrefix(line, name+"=") {
			return true
		}
	}
	return false
}

func casbinModelHasAttributeAccess(modelText string) bool {
	return strings.Contains(modelText, "r.sub.") ||
		strings.Contains(modelText, "r.obj.") ||
		strings.Contains(modelText, "eval(")
}
