package v2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/GoCodeAlone/workflow-plugin-authz/adminapi"
)

func TestV1InterfacesAndPolicyWireRemainUnchanged(t *testing.T) {
	t.Parallel()

	var _ v1.Provider = legacyProvider{}
	h, err := v1.NewHandler(v1.Options{
		PrincipalResolver: legacyResolver{},
		Authorizer:        legacyAuthorizer{},
		Provider:          legacyProvider{},
	})
	if err != nil {
		t.Fatalf("v1.NewHandler(): %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/policies", nil))
	const want = `[{"id":"legacy-1","resource":"status","action":"read","effect":"allow"}]` + "\n"
	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("v1 response = %d %q, want 200 %q", rec.Code, rec.Body.String(), want)
	}
}

type legacyResolver struct{}

func (legacyResolver) CurrentPrincipal(*http.Request) (v1.Principal, bool) {
	return v1.Principal{Subject: "legacy-admin"}, true
}

type legacyAuthorizer struct{}

func (legacyAuthorizer) Authorize(context.Context, v1.Principal, string, string) error { return nil }

type legacyProvider struct{}

func (legacyProvider) Roles(context.Context, v1.Principal) ([]v1.Role, error) { return nil, nil }
func (legacyProvider) UpsertRole(context.Context, v1.Principal, v1.RoleAssignment) error {
	return nil
}
func (legacyProvider) DeleteRole(context.Context, v1.Principal, v1.RoleAssignment) error {
	return nil
}
func (legacyProvider) Scopes(context.Context, v1.Principal) ([]v1.Scope, error) { return nil, nil }
func (legacyProvider) Capabilities(context.Context, v1.Principal) ([]v1.Capability, error) {
	return nil, nil
}
func (legacyProvider) Declarations(context.Context, v1.Principal) (v1.Declarations, error) {
	return v1.Declarations{}, nil
}
func (legacyProvider) ProjectionInputs(context.Context, v1.Principal) (v1.ProjectionInputs, error) {
	return v1.ProjectionInputs{}, nil
}
func (legacyProvider) Model(context.Context, v1.Principal) (v1.Model, error) {
	return v1.Model{}, nil
}

func (legacyProvider) Policies(context.Context, v1.Principal) ([]v1.Policy, error) {
	return []v1.Policy{{ID: "legacy-1", Resource: "status", Action: "read", Effect: "allow"}}, nil
}
func (legacyProvider) UpsertPolicy(context.Context, v1.Principal, v1.PolicyRule) error { return nil }
func (legacyProvider) DeletePolicy(context.Context, v1.Principal, v1.PolicyRule) error { return nil }
func (legacyProvider) AttributePolicies(context.Context, v1.Principal) ([]v1.AttributePolicy, error) {
	return nil, nil
}
func (legacyProvider) UpsertAttributePolicy(context.Context, v1.Principal, v1.AttributePolicy) error {
	return nil
}
func (legacyProvider) DeleteAttributePolicy(context.Context, v1.Principal, v1.AttributePolicy) error {
	return nil
}
func (legacyProvider) RelationTuples(context.Context, v1.Principal) ([]v1.RelationTuple, error) {
	return nil, nil
}
func (legacyProvider) UpsertRelationTuple(context.Context, v1.Principal, v1.RelationTuple) error {
	return nil
}
func (legacyProvider) DeleteRelationTuple(context.Context, v1.Principal, v1.RelationTuple) error {
	return nil
}
func (legacyProvider) CheckRelation(context.Context, v1.Principal, v1.RelationCheck) (v1.Decision, error) {
	return v1.Decision{}, nil
}
func (legacyProvider) Enforce(context.Context, v1.Principal, v1.DecisionRequest) (v1.Decision, error) {
	return v1.Decision{}, nil
}
