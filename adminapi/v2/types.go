// Package v2 exposes the canonical read-only authorization administration API.
package v2

import (
	"context"
	"errors"
	"net/http"
)

var (
	// ErrUnauthenticated reports that no trusted principal is available.
	ErrUnauthenticated = errors.New("authz principal is unauthenticated")
	// ErrForbidden reports a legitimate authorization denial.
	ErrForbidden = errors.New("authz request is forbidden")
	// ErrUnavailable reports an identity, authorization, or policy dependency failure.
	ErrUnavailable = errors.New("authz provider is unavailable")
	// ErrInvalidRequest reports invalid caller input.
	ErrInvalidRequest = errors.New("invalid authz request")
)

// Options supplies the host adapters and optional mount path.
type Options struct {
	BasePath          string
	PrincipalResolver PrincipalResolver
	Authorizer        Authorizer
	Provider          Provider
}

// Principal is the trusted authenticated identity used for every v2 request.
type Principal struct {
	Subject string `json:"subject"`
	Email   string `json:"email,omitempty"`
	Role    string `json:"role"`
}

// CapabilityDescriptor describes one configured authorization mode.
type CapabilityDescriptor struct {
	Mode              string   `json:"mode"`
	Operations        []string `json:"operations"`
	Configured        bool     `json:"configured"`
	Source            string   `json:"source"`
	Health            string   `json:"health"`
	UnsupportedReason string   `json:"unsupported_reason,omitempty"`
}

// Capabilities is the provider capability envelope consumed by the admin UI.
type Capabilities struct {
	Module              string                 `json:"module"`
	Provider            string                 `json:"provider"`
	Capabilities        []string               `json:"capabilities"`
	Descriptors         []CapabilityDescriptor `json:"capability_descriptors"`
	Health              string                 `json:"health"`
	MissingRequirements []string               `json:"missing_requirements,omitempty"`
}

// RoleAssignment is one host-owned principal-to-role projection.
type RoleAssignment struct {
	User    string   `json:"user"`
	Role    string   `json:"role"`
	Context string   `json:"context,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
}

// PolicyRule is one immutable direct-role policy row.
type PolicyRule struct {
	Subject string `json:"subject"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

// DecisionRequest intentionally excludes subject. Providers derive the
// effective subject or role from the authenticated Principal.
type DecisionRequest struct {
	Object string `json:"object"`
	Action string `json:"action"`
}

// Decision is the result of evaluating the authenticated principal's role.
type Decision struct {
	Allowed bool `json:"allowed"`
}

// PrincipalResolver resolves a trusted identity from the request.
type PrincipalResolver interface {
	CurrentPrincipal(*http.Request) (Principal, error)
}

// Authorizer protects each admin API operation before provider access.
type Authorizer interface {
	Authorize(context.Context, Principal, string, string) error
}

// Provider supplies the read-only authorization views and decisions.
type Provider interface {
	Capabilities(context.Context, Principal) (Capabilities, error)
	RoleAssignments(context.Context, Principal) ([]RoleAssignment, error)
	Policies(context.Context, Principal) ([]PolicyRule, error)
	Decide(context.Context, Principal, DecisionRequest) (Decision, error)
}
