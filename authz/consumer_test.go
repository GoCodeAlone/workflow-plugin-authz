package authz_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v2 "github.com/GoCodeAlone/workflow-plugin-authz/adminapi/v2"
	"github.com/GoCodeAlone/workflow-plugin-authz/authz"
)

const consumerModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

func TestRuntimeAdminAPIV2Consumer(t *testing.T) {
	t.Parallel()

	runtime, err := authz.NewRuntime(t.Context(), authz.RuntimeConfig{
		Model: consumerModel,
		Seed: &authz.SeedConfig{Policies: [][]string{
			{"super_admin", "admin:status", "read"},
		}},
	})
	if err != nil {
		t.Fatalf("authz.NewRuntime(): %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	handler, err := v2.NewHandler(v2.Options{
		PrincipalResolver: consumerResolver{},
		Authorizer:        consumerAuthorizer{},
		Provider:          consumerProvider{runtime: runtime},
	})
	if err != nil {
		t.Fatalf("v2.NewHandler(): %v", err)
	}

	for _, tt := range []struct {
		method string
		path   string
		body   string
		check  func(*testing.T, []byte)
	}{
		{method: http.MethodGet, path: "/api/authz/principal", check: func(t *testing.T, body []byte) {
			var principal v2.Principal
			if err := json.Unmarshal(body, &principal); err != nil || principal.Role != "super_admin" {
				t.Fatalf("principal = %#v, %v", principal, err)
			}
		}},
		{method: http.MethodGet, path: "/api/authz/policies", check: func(t *testing.T, body []byte) {
			var policies []v2.PolicyRule
			if err := json.Unmarshal(body, &policies); err != nil || len(policies) != 1 || policies[0].Subject != "super_admin" {
				t.Fatalf("policies = %#v, %v", policies, err)
			}
		}},
		{method: http.MethodPost, path: "/api/authz/decision", body: `{"object":"admin:status","action":"read"}`, check: func(t *testing.T, body []byte) {
			var decision v2.Decision
			if err := json.Unmarshal(body, &decision); err != nil || !decision.Allowed {
				t.Fatalf("decision = %#v, %v", decision, err)
			}
		}},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body)))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			tt.check(t, recorder.Body.Bytes())
		})
	}
}

type consumerResolver struct{}

func (consumerResolver) CurrentPrincipal(*http.Request) (v2.Principal, error) {
	return v2.Principal{Subject: "user-1", Email: "admin@example.test", Role: "super_admin"}, nil
}

type consumerAuthorizer struct{}

func (consumerAuthorizer) Authorize(context.Context, v2.Principal, string, string) error {
	return nil
}

type consumerProvider struct{ runtime *authz.Runtime }

func (consumerProvider) Capabilities(context.Context, v2.Principal) (v2.Capabilities, error) {
	return v2.Capabilities{
		Module: "authz", Provider: "casbin", Capabilities: []string{"rbac"},
		Descriptors: []v2.CapabilityDescriptor{{Mode: "rbac", Operations: []string{"check", "list"}, Configured: true, Source: "provider", Health: "ok"}},
		Health:      "ok",
	}, nil
}

func (consumerProvider) RoleAssignments(context.Context, v2.Principal) ([]v2.RoleAssignment, error) {
	return []v2.RoleAssignment{{User: "user-1", Role: "super_admin", Context: "admin"}}, nil
}

func (p consumerProvider) Policies(ctx context.Context, _ v2.Principal) ([]v2.PolicyRule, error) {
	policies, err := p.runtime.Policies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]v2.PolicyRule, len(policies))
	for i, policy := range policies {
		out[i] = v2.PolicyRule{Subject: policy.Subject, Object: policy.Object, Action: policy.Action}
	}
	return out, nil
}

func (p consumerProvider) Decide(ctx context.Context, principal v2.Principal, request v2.DecisionRequest) (v2.Decision, error) {
	decision, err := p.runtime.Decide(ctx, authz.DecisionRequest{Subject: principal.Role, Object: request.Object, Action: request.Action})
	return v2.Decision{Allowed: decision.Allowed}, err
}
