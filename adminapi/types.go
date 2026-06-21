// Package adminapi exposes reusable HTTP handlers for authz administration UIs.
package adminapi

import (
	"context"
	"net/http"
)

type Options struct {
	BasePath          string
	PrincipalResolver PrincipalResolver
	Authorizer        Authorizer
	Provider          Provider
}

type Principal struct {
	Subject string
	Email   string
	Role    string
}

type Role struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

type RoleAssignment struct {
	User    string   `json:"user"`
	Role    string   `json:"role"`
	Context string   `json:"context,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
}

type Scope struct {
	Name     string `json:"name"`
	Context  string `json:"context,omitempty"`
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
}

type Capability struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

type ResourceDeclaration struct {
	Name    string   `json:"name"`
	Actions []string `json:"actions,omitempty"`
}

type Declarations struct {
	Resources []ResourceDeclaration `json:"resources,omitempty"`
}

type ProjectionInputs struct {
	Subject  string   `json:"subject,omitempty"`
	Contexts []string `json:"contexts,omitempty"`
}

type Model struct {
	Provider string   `json:"provider,omitempty"`
	Modes    []string `json:"modes,omitempty"`
}

type Policy struct {
	ID       string `json:"id"`
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

type PolicyRule struct {
	Subject string `json:"subject"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

type AttributePolicy struct {
	ID       string `json:"id"`
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

type RelationTuple struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type RelationCheck struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type DecisionRequest struct {
	Subject  string `json:"subject"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Context  string `json:"context,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type PrincipalResolver interface {
	CurrentPrincipal(*http.Request) (Principal, bool)
}

type Authorizer interface {
	Authorize(context.Context, Principal, string, string) error
}

type Provider interface {
	Roles(context.Context, Principal) ([]Role, error)
	UpsertRole(context.Context, Principal, RoleAssignment) error
	DeleteRole(context.Context, Principal, RoleAssignment) error
	Scopes(context.Context, Principal) ([]Scope, error)
	Capabilities(context.Context, Principal) ([]Capability, error)
	Declarations(context.Context, Principal) (Declarations, error)
	ProjectionInputs(context.Context, Principal) (ProjectionInputs, error)
	Model(context.Context, Principal) (Model, error)
	Policies(context.Context, Principal) ([]Policy, error)
	UpsertPolicy(context.Context, Principal, PolicyRule) error
	DeletePolicy(context.Context, Principal, PolicyRule) error
	AttributePolicies(context.Context, Principal) ([]AttributePolicy, error)
	UpsertAttributePolicy(context.Context, Principal, AttributePolicy) error
	DeleteAttributePolicy(context.Context, Principal, AttributePolicy) error
	RelationTuples(context.Context, Principal) ([]RelationTuple, error)
	UpsertRelationTuple(context.Context, Principal, RelationTuple) error
	DeleteRelationTuple(context.Context, Principal, RelationTuple) error
	CheckRelation(context.Context, Principal, RelationCheck) (Decision, error)
	Enforce(context.Context, Principal, DecisionRequest) (Decision, error)
}

type RouteCatalog struct {
	ByPath map[string]Route
}

type Route struct {
	Name     string
	Method   string
	Path     string
	Resource string
	Action   string
}
