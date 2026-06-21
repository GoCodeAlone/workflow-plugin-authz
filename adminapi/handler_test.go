package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouteCatalogContainsAuthzUIBackendEndpoints(t *testing.T) {
	routes := DefaultRoutes()
	for _, want := range []string{
		"/api/authz/roles",
		"/api/authz/scopes",
		"/api/authz/capabilities",
		"/api/authz/declarations",
		"/api/authz/projection-inputs",
		"/api/authz/model",
		"/api/authz/policies",
		"/api/authz/abac/policies",
		"/api/authz/rebac/tuples",
		"/api/authz/rebac/check",
		"/api/authz/enforce",
	} {
		if _, ok := routes.ByPath[want]; !ok {
			t.Fatalf("route catalog missing %s; routes=%#v", want, routes.ByPath)
		}
	}
}

func TestNewHandlerRequiresRequiredAdapters(t *testing.T) {
	_, err := NewHandler(Options{})
	if err == nil {
		t.Fatal("NewHandler without auth adapters succeeded")
	}
	for _, want := range []string{"PrincipalResolver", "Authorizer", "Provider"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %s", err.Error(), want)
		}
	}
}

func TestHandlerDeniesUnauthenticatedAndUnauthorizedRequests(t *testing.T) {
	h, err := NewHandler(Options{
		PrincipalResolver: noPrincipal{},
		Authorizer:        allowAuthorizer{},
		Provider:          testProvider{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}

	h, err = NewHandler(Options{
		PrincipalResolver: fixedPrincipal{Principal{Subject: "user-1"}},
		Authorizer:        denyAuthorizer{},
		Provider:          testProvider{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/roles", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want 403", rec.Code)
	}
}

func TestHandlerServesAuthzUIReadRoutes(t *testing.T) {
	h := newTestHandler(t)

	for _, tc := range []struct {
		path     string
		wantType string
	}{
		{"/api/authz/roles", "array"},
		{"/api/authz/scopes", "array"},
		{"/api/authz/capabilities", "object"},
		{"/api/authz/declarations", "object"},
		{"/api/authz/projection-inputs", "object"},
		{"/api/authz/model", "object"},
		{"/api/authz/policies", "array"},
		{"/api/authz/abac/policies", "array"},
		{"/api/authz/rebac/tuples", "array"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
			}
			switch tc.wantType {
			case "array":
				var payload []any
				if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
					t.Fatalf("decode array JSON: %v; body=%s", err, rec.Body.String())
				}
			case "object":
				var payload map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
					t.Fatalf("decode object JSON: %v; body=%s", err, rec.Body.String())
				}
			}
		})
	}
}

func TestRolesReadReturnsRoleAssignmentsForAuthzUI(t *testing.T) {
	h := newTestHandler(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/roles", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	var assignments []RoleAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &assignments); err != nil {
		t.Fatalf("decode role assignments: %v", err)
	}
	if len(assignments) != 1 || assignments[0].User != "admin-1" || assignments[0].Role != "tenant_admin" || assignments[0].Context != "admin" {
		t.Fatalf("assignments = %#v, want admin-1 tenant_admin in admin context", assignments)
	}
	if len(assignments[0].Scopes) != 1 || assignments[0].Scopes[0] != "cms.page.read" {
		t.Fatalf("assignment scopes = %#v, want cms.page.read", assignments[0].Scopes)
	}
}

func TestRolesReadFallsBackToLegacyRoleDefinitions(t *testing.T) {
	h, err := NewHandler(Options{
		PrincipalResolver: fixedPrincipal{Principal{Subject: "admin-1"}},
		Authorizer:        allowAuthorizer{},
		Provider:          legacyRoleProvider{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/roles", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	var assignments []RoleAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &assignments); err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].Role != "tenant_admin" || len(assignments[0].Scopes) != 1 {
		t.Fatalf("assignments = %#v, want role-definition fallback", assignments)
	}
}

func TestHandlerReturnsJSONErrorsForUnknownOrWrongMethodAdminAPIRequests(t *testing.T) {
	h := newTestHandler(t)
	for _, tc := range []struct {
		name      string
		method    string
		path      string
		wantCode  int
		wantAllow string
	}{
		{name: "wrong method", method: http.MethodPut, path: "/api/authz/roles", wantCode: http.StatusMethodNotAllowed, wantAllow: "GET, POST, DELETE"},
		{name: "unknown path", method: http.MethodGet, path: "/api/authz/missing", wantCode: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", got)
			}
			if tc.wantAllow != "" && rec.Header().Get("Allow") != tc.wantAllow {
				t.Fatalf("Allow = %q, want %q", rec.Header().Get("Allow"), tc.wantAllow)
			}
			var payload struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode JSON error: %v body=%s", err, rec.Body.String())
			}
			if payload.Error == "" {
				t.Fatalf("error payload missing message: %s", rec.Body.String())
			}
		})
	}
}

func TestHandlerSupportsAuthzUIMutationRoutes(t *testing.T) {
	h := newTestHandler(t)
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/authz/roles", `{"user":"admin-1","role":"tenant_admin","context":"admin","scopes":["admin:authz.roles:read"]}`},
		{http.MethodDelete, "/api/authz/roles", `{"user":"admin-1","role":"tenant_admin","context":"admin"}`},
		{http.MethodPost, "/api/authz/policies", `{"subject":"admin","object":"cms.page","action":"read"}`},
		{http.MethodDelete, "/api/authz/policies", `{"subject":"admin","object":"cms.page","action":"read"}`},
		{http.MethodPost, "/api/authz/abac/policies", `{"id":"abac-1","resource":"cms.page","action":"read","effect":"allow"}`},
		{http.MethodDelete, "/api/authz/abac/policies", `{"id":"abac-1","resource":"cms.page","action":"read","effect":"allow"}`},
		{http.MethodPost, "/api/authz/rebac/tuples", `{"subject":"user:admin-1","relation":"member","object":"tenant:blackorchid"}`},
		{http.MethodDelete, "/api/authz/rebac/tuples", `{"subject":"user:admin-1","relation":"member","object":"tenant:blackorchid"}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandlerEnforceUsesProviderDecision(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/authz/enforce", strings.NewReader(`{"subject":"user-1","resource":"cms.page","action":"read","context":"tenant:blackorchid"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !payload.Allowed || payload.Reason != "matched test rule" {
		t.Fatalf("payload = %#v, want allowed test decision", payload)
	}
}

func TestHandlerRejectsClientAssertedSubjectWithoutPermission(t *testing.T) {
	h, err := NewHandler(Options{
		PrincipalResolver: fixedPrincipal{Principal{Subject: "user-1"}},
		Authorizer:        actionDenyAuthorizer{denyAction: "enforce"},
		Provider:          testProvider{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/authz/enforce", strings.NewReader(`{"subject":"super-admin","resource":"cms.page","action":"delete"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 body=%s", rec.Code, rec.Body.String())
	}
}

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := NewHandler(Options{
		PrincipalResolver: fixedPrincipal{Principal{Subject: "admin-1"}},
		Authorizer:        allowAuthorizer{},
		Provider:          testProvider{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

type noPrincipal struct{}

func (noPrincipal) CurrentPrincipal(*http.Request) (Principal, bool) { return Principal{}, false }

type fixedPrincipal struct{ principal Principal }

func (r fixedPrincipal) CurrentPrincipal(*http.Request) (Principal, bool) {
	return r.principal, true
}

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, Principal, string, string) error { return nil }

type denyAuthorizer struct{}

func (denyAuthorizer) Authorize(context.Context, Principal, string, string) error {
	return errors.New("denied")
}

type actionDenyAuthorizer struct{ denyAction string }

func (a actionDenyAuthorizer) Authorize(_ context.Context, _ Principal, _ string, action string) error {
	if action == a.denyAction {
		return errors.New("denied")
	}
	return nil
}

type testProvider struct{}

func (testProvider) Roles(context.Context, Principal) ([]Role, error) {
	return []Role{{Name: "tenant_admin", Scopes: []string{"cms.page.read"}}}, nil
}

func (testProvider) RoleAssignments(context.Context, Principal) ([]RoleAssignment, error) {
	return []RoleAssignment{{User: "admin-1", Role: "tenant_admin", Context: "admin", Scopes: []string{"cms.page.read"}}}, nil
}

func (testProvider) UpsertRole(context.Context, Principal, RoleAssignment) error { return nil }

func (testProvider) DeleteRole(context.Context, Principal, RoleAssignment) error { return nil }

func (testProvider) Scopes(context.Context, Principal) ([]Scope, error) {
	return []Scope{{Name: "cms.page.read", Resource: "cms.page", Action: "read"}}, nil
}

func (testProvider) Capabilities(context.Context, Principal) ([]Capability, error) {
	return []Capability{{Name: "rbac", Supported: true}}, nil
}

func (testProvider) Declarations(context.Context, Principal) (Declarations, error) {
	return Declarations{Resources: []ResourceDeclaration{{Name: "cms.page", Actions: []string{"read"}}}}, nil
}

func (testProvider) ProjectionInputs(context.Context, Principal) (ProjectionInputs, error) {
	return ProjectionInputs{Subject: "admin-1", Contexts: []string{"tenant:blackorchid"}}, nil
}

func (testProvider) Model(context.Context, Principal) (Model, error) {
	return Model{Provider: "test", Modes: []string{"rbac"}}, nil
}

func (testProvider) Policies(context.Context, Principal) ([]Policy, error) {
	return []Policy{{ID: "policy-1", Resource: "cms.page", Action: "read", Effect: "allow"}}, nil
}

func (testProvider) UpsertPolicy(context.Context, Principal, PolicyRule) error { return nil }

func (testProvider) DeletePolicy(context.Context, Principal, PolicyRule) error { return nil }

func (testProvider) AttributePolicies(context.Context, Principal) ([]AttributePolicy, error) {
	return []AttributePolicy{{ID: "abac-1", Resource: "cms.page", Action: "read", Effect: "allow"}}, nil
}

func (testProvider) UpsertAttributePolicy(context.Context, Principal, AttributePolicy) error {
	return nil
}

func (testProvider) DeleteAttributePolicy(context.Context, Principal, AttributePolicy) error {
	return nil
}

func (testProvider) RelationTuples(context.Context, Principal) ([]RelationTuple, error) {
	return []RelationTuple{{Subject: "user:admin-1", Relation: "member", Object: "tenant:blackorchid"}}, nil
}

func (testProvider) UpsertRelationTuple(context.Context, Principal, RelationTuple) error {
	return nil
}

func (testProvider) DeleteRelationTuple(context.Context, Principal, RelationTuple) error {
	return nil
}

func (testProvider) CheckRelation(context.Context, Principal, RelationCheck) (Decision, error) {
	return Decision{Allowed: true, Reason: "matched relation"}, nil
}

func (testProvider) Enforce(context.Context, Principal, DecisionRequest) (Decision, error) {
	return Decision{Allowed: true, Reason: "matched test rule"}, nil
}

type legacyRoleProvider struct{}

func (legacyRoleProvider) Roles(context.Context, Principal) ([]Role, error) {
	return []Role{{Name: "tenant_admin", Scopes: []string{"cms.page.read"}}}, nil
}

func (legacyRoleProvider) UpsertRole(ctx context.Context, p Principal, r RoleAssignment) error {
	return testProvider{}.UpsertRole(ctx, p, r)
}

func (legacyRoleProvider) DeleteRole(ctx context.Context, p Principal, r RoleAssignment) error {
	return testProvider{}.DeleteRole(ctx, p, r)
}

func (legacyRoleProvider) Scopes(ctx context.Context, p Principal) ([]Scope, error) {
	return testProvider{}.Scopes(ctx, p)
}

func (legacyRoleProvider) Capabilities(ctx context.Context, p Principal) ([]Capability, error) {
	return testProvider{}.Capabilities(ctx, p)
}

func (legacyRoleProvider) Declarations(ctx context.Context, p Principal) (Declarations, error) {
	return testProvider{}.Declarations(ctx, p)
}

func (legacyRoleProvider) ProjectionInputs(ctx context.Context, p Principal) (ProjectionInputs, error) {
	return testProvider{}.ProjectionInputs(ctx, p)
}

func (legacyRoleProvider) Model(ctx context.Context, p Principal) (Model, error) {
	return testProvider{}.Model(ctx, p)
}

func (legacyRoleProvider) Policies(ctx context.Context, p Principal) ([]Policy, error) {
	return testProvider{}.Policies(ctx, p)
}

func (legacyRoleProvider) UpsertPolicy(ctx context.Context, p Principal, r PolicyRule) error {
	return testProvider{}.UpsertPolicy(ctx, p, r)
}

func (legacyRoleProvider) DeletePolicy(ctx context.Context, p Principal, r PolicyRule) error {
	return testProvider{}.DeletePolicy(ctx, p, r)
}

func (legacyRoleProvider) AttributePolicies(ctx context.Context, p Principal) ([]AttributePolicy, error) {
	return testProvider{}.AttributePolicies(ctx, p)
}

func (legacyRoleProvider) UpsertAttributePolicy(ctx context.Context, p Principal, policy AttributePolicy) error {
	return testProvider{}.UpsertAttributePolicy(ctx, p, policy)
}

func (legacyRoleProvider) DeleteAttributePolicy(ctx context.Context, p Principal, policy AttributePolicy) error {
	return testProvider{}.DeleteAttributePolicy(ctx, p, policy)
}

func (legacyRoleProvider) RelationTuples(ctx context.Context, p Principal) ([]RelationTuple, error) {
	return testProvider{}.RelationTuples(ctx, p)
}

func (legacyRoleProvider) UpsertRelationTuple(ctx context.Context, p Principal, tuple RelationTuple) error {
	return testProvider{}.UpsertRelationTuple(ctx, p, tuple)
}

func (legacyRoleProvider) DeleteRelationTuple(ctx context.Context, p Principal, tuple RelationTuple) error {
	return testProvider{}.DeleteRelationTuple(ctx, p, tuple)
}

func (legacyRoleProvider) CheckRelation(ctx context.Context, p Principal, check RelationCheck) (Decision, error) {
	return testProvider{}.CheckRelation(ctx, p, check)
}

func (legacyRoleProvider) Enforce(ctx context.Context, p Principal, req DecisionRequest) (Decision, error) {
	return testProvider{}.Enforce(ctx, p, req)
}
