package internal

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

const (
	defaultPermitAPIURL = "https://api.permit.io"
	defaultPermitPDPURL = "https://cloudpdp.api.permit.io"
)

// PermitModule implements sdk.ModuleInstance for the permit.provider module type.
// Scope-role APIs use the official Permit.io Go SDK. Legacy step helpers still
// use the old registered client until those unused step contracts are removed.
type PermitModule struct {
	name          string
	config        permitModuleConfig
	client        *permitClient
	scopeProvider *permitScopeProvider
}

// permitModuleConfig holds parsed configuration for a permit.provider module.
type permitModuleConfig struct {
	APIKey      string `yaml:"apiKey"`
	PDPURL      string `yaml:"pdpUrl"`
	APIURL      string `yaml:"apiUrl"`
	Project     string `yaml:"project"`
	Environment string `yaml:"environment"`
}

// newPermitModule parses the config map and returns a PermitModule.
func newPermitModule(name string, config map[string]any) (*PermitModule, error) {
	apiKey, _ := config["apiKey"].(string)
	if apiKey == "" {
		return nil, fmt.Errorf("permit.provider %q: config.apiKey is required", name)
	}

	pdpURL, _ := config["pdpUrl"].(string)
	if pdpURL == "" {
		pdpURL = defaultPermitPDPURL
	}

	apiURL, _ := config["apiUrl"].(string)
	if apiURL == "" {
		apiURL = defaultPermitAPIURL
	}

	project, _ := config["project"].(string)
	environment, _ := config["environment"].(string)

	return &PermitModule{
		name: name,
		config: permitModuleConfig{
			APIKey:      apiKey,
			PDPURL:      pdpURL,
			APIURL:      apiURL,
			Project:     project,
			Environment: environment,
		},
	}, nil
}

// Init creates the HTTP client and registers it in the global permit registry.
func (m *PermitModule) Init() error {
	m.scopeProvider = newPermitScopeProvider(m.name, newPermitSDKScopeClient(m.config))
	m.client = &permitClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL:      m.config.APIURL,
		pdpURL:      m.config.PDPURL,
		apiKey:      m.config.APIKey,
		project:     m.config.Project,
		environment: m.config.Environment,
	}
	RegisterPermitClient(m.name, m.client)
	return nil
}

// Start is a no-op for the permit module.
func (m *PermitModule) Start(_ context.Context) error { return nil }

// Stop removes the client from the registry.
func (m *PermitModule) Stop(_ context.Context) error {
	UnregisterPermitClient(m.name)
	return nil
}

// Name returns the module name.
func (m *PermitModule) Name() string { return m.name }

func (m *PermitModule) DeclareScopes(ctx context.Context, scopes []*contracts.ScopeDeclaration) error {
	return m.scopeProvider.DeclareScopes(ctx, scopes)
}

func (m *PermitModule) UpsertRole(ctx context.Context, grant RoleScopeGrant) error {
	return m.scopeProvider.UpsertRole(ctx, grant)
}

func (m *PermitModule) AssignRole(ctx context.Context, assignment SubjectRoleAssignment) error {
	return m.scopeProvider.AssignRole(ctx, assignment)
}

func (m *PermitModule) ListAssignments(ctx context.Context, filter AssignmentFilter) ([]SubjectRoleAssignment, error) {
	return m.scopeProvider.ListAssignments(ctx, filter)
}

func (m *PermitModule) RemoveAssignment(ctx context.Context, assignment SubjectRoleAssignment) error {
	return m.scopeProvider.RemoveAssignment(ctx, assignment)
}

func (m *PermitModule) CheckScope(ctx context.Context, check ScopeCheck) (ScopeCheckResult, error) {
	return m.scopeProvider.CheckScope(ctx, check)
}

func (m *PermitModule) InvokeMethod(method string, input map[string]any) (map[string]any, error) {
	switch method {
	case "GetCapabilities":
		return providerCapabilitiesInvoke(m.name, "permit", m, input, false)
	case "RequireCapabilities":
		return providerCapabilitiesInvoke(m.name, "permit", m, input, true)
	default:
		return nil, fmt.Errorf("permit provider method %q is not supported", method)
	}
}
