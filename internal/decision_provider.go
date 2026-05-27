package internal

import (
	"context"
	"fmt"
)

type AuthorizationDecisionInput struct {
	Provider              string
	Mode                  AuthzCapability
	Subject               string
	Context               string
	Resource              string
	Action                string
	Scope                 string
	Relation              string
	SubjectAttributes     map[string]string
	ResourceAttributes    map[string]string
	EnvironmentAttributes map[string]string
	Explain               bool
}

type AuthorizationDecisionOutput struct {
	Allowed bool
	Mode    AuthzCapability
	Subject string
	Context string
	Reason  string
	Explain string
}

func DecideAuthorization(ctx context.Context, provider any, input AuthorizationDecisionInput) (AuthorizationDecisionOutput, error) {
	mode, err := selectDecisionMode(provider, input)
	if err != nil {
		return AuthorizationDecisionOutput{}, err
	}
	switch mode {
	case CapabilityRBAC:
		scopeProvider, ok := provider.(ScopeRoleProvider)
		if !ok {
			return AuthorizationDecisionOutput{}, fmt.Errorf("provider does not implement RBAC scope checks")
		}
		result, err := scopeProvider.CheckScope(ctx, ScopeCheck{
			Subject:  input.Subject,
			Context:  input.Context,
			Scope:    input.Scope,
			Resource: input.Resource,
			Action:   input.Action,
		})
		if err != nil {
			return AuthorizationDecisionOutput{}, err
		}
		return AuthorizationDecisionOutput{Allowed: result.Allowed, Mode: CapabilityRBAC, Subject: result.Subject, Context: result.Context, Reason: result.Reason, Explain: result.MatchedRole}, nil
	case CapabilityABAC:
		attributeProvider, ok := provider.(AttributePolicyProvider)
		if !ok {
			return AuthorizationDecisionOutput{}, fmt.Errorf("provider does not implement ABAC checks")
		}
		result, err := attributeProvider.CheckAttributes(ctx, AttributeCheck{
			Subject:               input.Subject,
			Context:               input.Context,
			Resource:              input.Resource,
			Action:                input.Action,
			SubjectAttributes:     input.SubjectAttributes,
			ResourceAttributes:    input.ResourceAttributes,
			EnvironmentAttributes: input.EnvironmentAttributes,
		})
		if err != nil {
			return AuthorizationDecisionOutput{}, err
		}
		return AuthorizationDecisionOutput{Allowed: result.Allowed, Mode: CapabilityABAC, Subject: result.Subject, Context: result.Context, Reason: result.Reason, Explain: result.MatchedPolicyID}, nil
	case CapabilityReBAC:
		relationshipProvider, ok := provider.(RelationshipProvider)
		if !ok {
			return AuthorizationDecisionOutput{}, fmt.Errorf("provider does not implement ReBAC checks")
		}
		result, err := relationshipProvider.CheckRelation(ctx, RelationCheck{
			Subject:  input.Subject,
			Context:  input.Context,
			Object:   input.Resource,
			Relation: input.Relation,
		})
		if err != nil {
			return AuthorizationDecisionOutput{}, err
		}
		return AuthorizationDecisionOutput{Allowed: result.Allowed, Mode: CapabilityReBAC, Subject: result.Subject, Context: result.Context, Reason: result.Reason, Explain: result.Relation}, nil
	default:
		return AuthorizationDecisionOutput{}, fmt.Errorf("unsupported authorization mode %q", mode)
	}
}

func selectDecisionMode(provider any, input AuthorizationDecisionInput) (AuthzCapability, error) {
	if input.Mode != "" {
		if authzProvider, ok := provider.(AuthzProvider); ok && !authzProvider.SupportsCapability(input.Mode) {
			return "", fmt.Errorf("provider does not support authorization mode %q", input.Mode)
		}
		return input.Mode, nil
	}
	hasScope := input.Scope != "" || (input.Resource != "" && input.Action != "" && input.Relation == "" && len(input.SubjectAttributes) == 0 && len(input.ResourceAttributes) == 0)
	hasAttrs := len(input.SubjectAttributes) > 0 || len(input.ResourceAttributes) > 0 || len(input.EnvironmentAttributes) > 0
	hasRelation := input.Relation != ""
	count := 0
	var mode AuthzCapability
	if hasScope {
		count++
		mode = CapabilityRBAC
	}
	if hasAttrs {
		count++
		mode = CapabilityABAC
	}
	if hasRelation {
		count++
		mode = CapabilityReBAC
	}
	if count != 1 {
		return "", fmt.Errorf("authorization decision mode is ambiguous; set mode explicitly")
	}
	if authzProvider, ok := provider.(AuthzProvider); ok && !authzProvider.SupportsCapability(mode) {
		return "", fmt.Errorf("provider does not support authorization mode %q", mode)
	}
	return mode, nil
}
