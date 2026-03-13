package internal

import (
	"context"
	"fmt"

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
	return []AuthzCapability{CapabilityRBAC, CapabilityABAC, CapabilityACL}
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
		_, ok := GetPermitClient(s.moduleName)
		if !ok {
			return nil, fmt.Errorf("step.authz_capabilities %q: permit module %q not found", s.name, s.moduleName)
		}
		// We need a PermitModule to call Capabilities; create a minimal one.
		provider = &PermitModule{name: s.moduleName}
	default:
		return nil, fmt.Errorf("step.authz_capabilities %q: unknown provider %q (expected \"casbin\" or \"permit\")", s.name, s.provider)
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
