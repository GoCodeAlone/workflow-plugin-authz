package authzcontract

import (
	"fmt"
	"strings"
)

const (
	CasbinModuleType = "authz.casbin"
	EffectAllow      = "allow"
	EffectDeny       = "deny"
)

// CasbinPolicyConfig is the public JSON/YAML contract for hosts that consume
// authz.casbin policy shape without importing plugin internals.
type CasbinPolicyConfig struct {
	Type                 string              `json:"type,omitempty" yaml:"type,omitempty"`
	Config               *CasbinPolicyConfig `json:"config,omitempty" yaml:"config,omitempty"`
	Model                string              `json:"model,omitempty" yaml:"model,omitempty"`
	DefaultEffect        string              `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	Policies             [][]string          `json:"policies,omitempty" yaml:"policies,omitempty"`
	RoleAssignments      [][]string          `json:"role_assignments,omitempty" yaml:"role_assignments,omitempty"`
	RoleAssignmentsCamel [][]string          `json:"roleAssignments,omitempty" yaml:"roleAssignments,omitempty"`
}

func NormalizeCasbinPolicyConfig(policy CasbinPolicyConfig) (CasbinPolicyConfig, error) {
	policy.Type = strings.TrimSpace(policy.Type)
	if policy.Type == "" {
		policy.Type = CasbinModuleType
	}
	if policy.Type != CasbinModuleType {
		return CasbinPolicyConfig{}, fmt.Errorf("unsupported authorization policy type %q", policy.Type)
	}
	policy.Model = strings.TrimSpace(policy.Model)
	policy.DefaultEffect = normalizeEffect(policy.DefaultEffect)
	policy.Policies = cloneStringRows(policy.Policies)
	policy.RoleAssignments = append(cloneStringRows(policy.RoleAssignments), cloneStringRows(policy.RoleAssignmentsCamel)...)
	policy.RoleAssignmentsCamel = nil
	if policy.Config == nil {
		return policy, nil
	}
	config, err := NormalizeCasbinPolicyConfig(*policy.Config)
	if err != nil {
		return CasbinPolicyConfig{}, err
	}
	policy.Config = nil
	if config.Model != "" {
		policy.Model = config.Model
	}
	if config.DefaultEffect != "" {
		policy.DefaultEffect = config.DefaultEffect
	}
	policy.Policies = append(policy.Policies, config.Policies...)
	policy.RoleAssignments = append(policy.RoleAssignments, config.RoleAssignments...)
	return policy, nil
}

func normalizeEffect(effect string) string {
	switch strings.ToLower(strings.TrimSpace(effect)) {
	case EffectAllow:
		return EffectAllow
	case EffectDeny:
		return EffectDeny
	default:
		return ""
	}
}

func cloneStringRows(rows [][]string) [][]string {
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, append([]string(nil), row...))
	}
	return out
}
