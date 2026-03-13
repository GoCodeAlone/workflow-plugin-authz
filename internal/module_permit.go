package internal

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultPermitAPIURL = "https://api.permit.io"
	defaultPermitPDPURL = "https://cloudpdp.api.permit.io"
)

// PermitModule implements sdk.ModuleInstance for the permit.provider module type.
// It creates and registers a permitClient backed by direct HTTP calls to the
// Permit.io management API and PDP API.
type PermitModule struct {
	name   string
	config permitModuleConfig
	client *permitClient
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
