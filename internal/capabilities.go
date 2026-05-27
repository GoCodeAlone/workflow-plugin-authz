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

// AuthzOperation is a provider-neutral operation that can be performed for an
// authorization mode. Operations are intentionally narrow so providers do not
// advertise management surfaces they have not implemented.
type AuthzOperation string

const (
	OperationCheck           AuthzOperation = "check"
	OperationManageRoles     AuthzOperation = "manage_roles"
	OperationManagePolicies  AuthzOperation = "manage_policies"
	OperationManageRelations AuthzOperation = "manage_relations"
	OperationList            AuthzOperation = "list"
)

// CapabilityRequirement describes the mode and operations a consumer needs.
type CapabilityRequirement struct {
	Mode       AuthzCapability
	Operations []AuthzOperation
}

// CapabilityDescriptor describes a provider mode, the implemented operations,
// and whether the provider is healthy enough to use that mode.
type CapabilityDescriptor struct {
	Mode              AuthzCapability
	Operations        []AuthzOperation
	Configured        bool
	Source            string
	Health            string
	UnsupportedReason string
}

// AuthzProvider is implemented by authorization providers to declare their
// supported authorization models.
type AuthzProvider interface {
	Capabilities() []AuthzCapability
	SupportsCapability(AuthzCapability) bool
	CapabilityDescriptors() []CapabilityDescriptor
	RequireCapabilities([]CapabilityRequirement) error
}

// Capabilities returns the authorization models supported by Casbin.
func (m *CasbinModule) Capabilities() []AuthzCapability {
	descriptors := m.CapabilityDescriptors()
	capabilities := make([]AuthzCapability, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Configured && descriptor.UnsupportedReason == "" {
			capabilities = append(capabilities, descriptor.Mode)
		}
	}
	return capabilities
}

// CapabilityDescriptors returns Casbin authorization modes detected from the
// configured model and only includes operations the adapter exposes.
func (m *CasbinModule) CapabilityDescriptors() []CapabilityDescriptor {
	modelText := strings.ToLower(m.config.Model)
	descriptors := make([]CapabilityDescriptor, 0, 4)
	if casbinModelHasRoleDefinition(modelText, "g") {
		descriptors = append(descriptors, newCapabilityDescriptor(
			CapabilityRBAC,
			[]AuthzOperation{OperationCheck, OperationManageRoles},
			"detected",
		))
	}
	if casbinModelHasRoleDefinition(modelText, "g2") || strings.Contains(modelText, "g2(") {
		descriptors = append(descriptors, newCapabilityDescriptor(
			CapabilityReBAC,
			[]AuthzOperation{OperationCheck, OperationManageRelations, OperationList},
			"detected",
		))
	}
	if casbinModelHasAttributeAccess(modelText) {
		descriptors = append(descriptors, newCapabilityDescriptor(
			CapabilityABAC,
			[]AuthzOperation{OperationCheck, OperationManagePolicies},
			"detected",
		))
	}
	if len(descriptors) == 0 {
		descriptors = append(descriptors, newCapabilityDescriptor(
			CapabilityACL,
			[]AuthzOperation{OperationCheck, OperationManagePolicies, OperationList},
			"detected",
		))
	}
	return descriptors
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

func (m *CasbinModule) RequireCapabilities(requirements []CapabilityRequirement) error {
	return requireCapabilities("casbin", m.CapabilityDescriptors(), requirements)
}

// Capabilities returns the authorization models supported by Permit.io.
func (m *PermitModule) Capabilities() []AuthzCapability {
	return capabilitiesFromDescriptors(m.CapabilityDescriptors())
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

// CapabilityDescriptors returns the provider-neutral Permit operations exposed
// by this adapter today. More Permit-native ABAC/ReBAC operations are added by
// later adapter phases; they are not advertised until implemented.
func (m *PermitModule) CapabilityDescriptors() []CapabilityDescriptor {
	return []CapabilityDescriptor{
		newCapabilityDescriptor(
			CapabilityRBAC,
			[]AuthzOperation{OperationCheck, OperationManageRoles},
			"provider",
		),
	}
}

func (m *PermitModule) RequireCapabilities(requirements []CapabilityRequirement) error {
	return requireCapabilities("permit", m.CapabilityDescriptors(), requirements)
}

// Capabilities returns authorization models represented by the Keto adapter.
func (m *KetoModule) Capabilities() []AuthzCapability {
	return capabilitiesFromDescriptors(m.CapabilityDescriptors())
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

// CapabilityDescriptors returns the provider-neutral operations implemented by
// the Keto adapter.
func (m *KetoModule) CapabilityDescriptors() []CapabilityDescriptor {
	return []CapabilityDescriptor{
		newCapabilityDescriptor(
			CapabilityRBAC,
			[]AuthzOperation{OperationCheck, OperationManageRoles},
			"provider",
		),
		newCapabilityDescriptor(
			CapabilityReBAC,
			[]AuthzOperation{OperationCheck, OperationManageRelations, OperationList},
			"provider",
		),
	}
}

func (m *KetoModule) RequireCapabilities(requirements []CapabilityRequirement) error {
	return requireCapabilities("keto", m.CapabilityDescriptors(), requirements)
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
	descriptors := capabilityDescriptorsToMaps(provider.CapabilityDescriptors())

	return &sdk.StepResult{
		Output: map[string]any{
			"provider":               s.provider,
			"module":                 s.moduleName,
			"capabilities":           capStrings,
			"capability_descriptors": descriptors,
			"health":                 providerHealth(provider.CapabilityDescriptors()),
		},
	}, nil
}

func newCapabilityDescriptor(mode AuthzCapability, operations []AuthzOperation, source string) CapabilityDescriptor {
	return CapabilityDescriptor{
		Mode:       mode,
		Operations: copyAuthzOperations(operations),
		Configured: true,
		Source:     source,
		Health:     "ok",
	}
}

func capabilitiesFromDescriptors(descriptors []CapabilityDescriptor) []AuthzCapability {
	out := make([]AuthzCapability, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Configured && descriptor.UnsupportedReason == "" {
			out = append(out, descriptor.Mode)
		}
	}
	return out
}

func requireCapabilities(providerName string, descriptors []CapabilityDescriptor, requirements []CapabilityRequirement) error {
	missing := missingCapabilityRequirements(descriptors, requirements)
	if len(missing) > 0 {
		return fmt.Errorf("%s provider missing required capabilities: %s", providerName, strings.Join(missing, ", "))
	}
	return nil
}

func missingCapabilityRequirements(descriptors []CapabilityDescriptor, requirements []CapabilityRequirement) []string {
	byMode := make(map[AuthzCapability]CapabilityDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byMode[descriptor.Mode] = descriptor
	}
	missing := make([]string, 0)
	for _, requirement := range requirements {
		descriptor, ok := byMode[requirement.Mode]
		if !ok || !descriptor.Configured || descriptor.UnsupportedReason != "" {
			missing = append(missing, string(requirement.Mode))
			continue
		}
		ops := make(map[AuthzOperation]bool, len(descriptor.Operations))
		for _, operation := range descriptor.Operations {
			ops[operation] = true
		}
		for _, operation := range requirement.Operations {
			if !ops[operation] {
				missing = append(missing, fmt.Sprintf("%s:%s", requirement.Mode, operation))
			}
		}
	}
	return missing
}

func providerCapabilitiesOutputMap(moduleName, providerName string, provider AuthzProvider, requirements []CapabilityRequirement) map[string]any {
	descriptors := provider.CapabilityDescriptors()
	caps := capabilitiesFromDescriptors(descriptors)
	capStrings := make([]any, 0, len(caps))
	for _, cap := range caps {
		capStrings = append(capStrings, string(cap))
	}
	missing := missingCapabilityRequirements(descriptors, requirements)
	missingStrings := make([]any, 0, len(missing))
	for _, item := range missing {
		missingStrings = append(missingStrings, item)
	}
	return map[string]any{
		"module":                 moduleName,
		"provider":               providerName,
		"capabilities":           capStrings,
		"capability_descriptors": capabilityDescriptorsToMaps(descriptors),
		"health":                 providerHealth(descriptors),
		"missing_requirements":   missingStrings,
	}
}

func providerCapabilitiesInvoke(moduleName, providerName string, provider AuthzProvider, input map[string]any, require bool) (map[string]any, error) {
	requirements := capabilityRequirementsFromAny(input["requirements"])
	out := providerCapabilitiesOutputMap(moduleName, providerName, provider, requirements)
	if require {
		if err := provider.RequireCapabilities(requirements); err != nil {
			return out, err
		}
	}
	return out, nil
}

func capabilityRequirementsFromAny(value any) []CapabilityRequirement {
	switch values := value.(type) {
	case []CapabilityRequirement:
		return append([]CapabilityRequirement(nil), values...)
	case []any:
		out := make([]CapabilityRequirement, 0, len(values))
		for _, value := range values {
			requirement := capabilityRequirementFromMap(mapValue(value))
			if requirement.Mode != "" {
				out = append(out, requirement)
			}
		}
		return out
	default:
		return nil
	}
}

func capabilityRequirementFromMap(values map[string]any) CapabilityRequirement {
	return CapabilityRequirement{
		Mode:       AuthzCapability(stringValue(values["mode"])),
		Operations: authzOperationsFromStrings(stringSliceValue(values["operations"])),
	}
}

func authzOperationsFromStrings(values []string) []AuthzOperation {
	out := make([]AuthzOperation, 0, len(values))
	for _, value := range values {
		out = append(out, AuthzOperation(value))
	}
	return out
}

func capabilityDescriptorsToMaps(descriptors []CapabilityDescriptor) []any {
	out := make([]any, 0, len(descriptors))
	for _, descriptor := range descriptors {
		ops := make([]any, 0, len(descriptor.Operations))
		for _, operation := range descriptor.Operations {
			ops = append(ops, string(operation))
		}
		out = append(out, map[string]any{
			"mode":               string(descriptor.Mode),
			"operations":         ops,
			"configured":         descriptor.Configured,
			"source":             descriptor.Source,
			"health":             descriptor.Health,
			"unsupported_reason": descriptor.UnsupportedReason,
		})
	}
	return out
}

func providerHealth(descriptors []CapabilityDescriptor) string {
	if len(descriptors) == 0 {
		return "degraded"
	}
	for _, descriptor := range descriptors {
		if descriptor.Health != "ok" {
			return "degraded"
		}
	}
	return "ok"
}

func copyAuthzOperations(in []AuthzOperation) []AuthzOperation {
	out := make([]AuthzOperation, len(in))
	copy(out, in)
	return out
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
