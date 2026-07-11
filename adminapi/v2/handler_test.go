package v2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerGoldenReadContract(t *testing.T) {
	t.Parallel()

	h := newGoldenHandler(t)
	for _, tt := range []struct {
		method string
		path   string
		body   string
		want   string
	}{
		{method: http.MethodGet, path: "/api/authz/principal", want: `{"subject":"user-1","email":"admin@example.test","role":"super_admin"}` + "\n"},
		{method: http.MethodGet, path: "/api/authz/capabilities", want: `{"module":"authz","provider":"casbin","capabilities":["rbac"],"capability_descriptors":[{"mode":"rbac","operations":["check","list"],"configured":true,"source":"provider","health":"ok"}],"health":"ok"}` + "\n"},
		{method: http.MethodGet, path: "/api/authz/roles", want: `[{"user":"user-1","role":"super_admin","context":"admin","scopes":["admin:core-dump.authz:read"]}]` + "\n"},
		{method: http.MethodGet, path: "/api/authz/policies", want: `[{"subject":"super_admin","object":"admin:status","action":"read"}]` + "\n"},
		{method: http.MethodPost, path: "/api/authz/decision", body: `{"object":"admin:status","action":"read"}`, want: `{"allowed":true}` + "\n"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Body.String() != tt.want {
				t.Fatalf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), tt.want)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Fatalf("Content-Type = %q", got)
			}
		})
	}
}

func TestHandlerMapsTypedFailuresAndRedactsProviderErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		resolver   PrincipalResolver
		authorizer Authorizer
		provider   Provider
		wantCode   int
		wantBody   string
	}{
		{name: "unauthenticated", resolver: errorResolver{ErrUnauthenticated}, authorizer: allowAuthorizer{}, provider: goldenProvider{}, wantCode: http.StatusUnauthorized, wantBody: `{"error":"unauthorized"}` + "\n"},
		{name: "identity unavailable", resolver: errorResolver{errors.New("secret identity store")}, authorizer: allowAuthorizer{}, provider: goldenProvider{}, wantCode: http.StatusServiceUnavailable, wantBody: `{"error":"authz provider unavailable"}` + "\n"},
		{name: "forbidden", resolver: goldenResolver{}, authorizer: errorAuthorizer{ErrForbidden}, provider: goldenProvider{}, wantCode: http.StatusForbidden, wantBody: `{"error":"forbidden"}` + "\n"},
		{name: "authorizer unavailable", resolver: goldenResolver{}, authorizer: errorAuthorizer{errors.Join(ErrUnavailable, errors.New("secret authorizer"))}, provider: goldenProvider{}, wantCode: http.StatusServiceUnavailable, wantBody: `{"error":"authz provider unavailable"}` + "\n"},
		{name: "provider unavailable", resolver: goldenResolver{}, authorizer: allowAuthorizer{}, provider: errorProvider{err: errors.Join(ErrUnavailable, errors.New("secret DSN"))}, wantCode: http.StatusServiceUnavailable, wantBody: `{"error":"authz provider unavailable"}` + "\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, err := NewHandler(Options{PrincipalResolver: tt.resolver, Authorizer: tt.authorizer, Provider: tt.provider})
			if err != nil {
				t.Fatalf("NewHandler(): %v", err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/authz/policies", nil))
			if rec.Code != tt.wantCode || rec.Body.String() != tt.wantBody {
				t.Fatalf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantCode, tt.wantBody)
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Fatalf("response exposed provider details: %s", rec.Body.String())
			}
		})
	}
}

func TestHandlerRejectsMalformedOrSubjectSelectingDecision(t *testing.T) {
	t.Parallel()

	h := newGoldenHandler(t)
	for _, body := range []string{
		`{"object":`,
		`{"object":"admin:status","action":"read"}{}`,
		`{"subject":"other","object":"admin:status","action":"read"}`,
		`{"object":"","action":"read"}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/authz/decision", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid authz request"}`+"\n" {
			t.Fatalf("body %q response = %d %q", body, rec.Code, rec.Body.String())
		}
	}
}

func TestHandlerRejectsKnownMutationsBeforeIdentity(t *testing.T) {
	t.Parallel()

	resolver := &countingResolver{}
	h, err := NewHandler(Options{PrincipalResolver: resolver, Authorizer: allowAuthorizer{}, Provider: goldenProvider{}})
	if err != nil {
		t.Fatalf("NewHandler(): %v", err)
	}
	for _, tt := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/authz/policies"},
		{http.MethodDelete, "/api/authz/policies"},
		{http.MethodPost, "/api/authz/roles"},
		{http.MethodDelete, "/api/authz/roles"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("%s %s = %d Allow=%q", tt.method, tt.path, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if resolver.calls != 0 {
		t.Fatalf("mutation rejection resolved principal %d times", resolver.calls)
	}
}

func TestHandlerCanonicalizesNilCollections(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(Options{PrincipalResolver: goldenResolver{}, Authorizer: allowAuthorizer{}, Provider: nilCollectionProvider{}})
	if err != nil {
		t.Fatalf("NewHandler(): %v", err)
	}
	for _, tt := range []struct {
		path string
		want string
	}{
		{path: "/api/authz/roles", want: "[]\n"},
		{path: "/api/authz/policies", want: "[]\n"},
		{path: "/api/authz/capabilities", want: `{"module":"authz","provider":"casbin","capabilities":[],"capability_descriptors":[],"health":"ok"}` + "\n"},
	} {
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != tt.want {
			t.Fatalf("%s response = %d %q, want %q", tt.path, recorder.Code, recorder.Body.String(), tt.want)
		}
	}
}

func newGoldenHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := NewHandler(Options{PrincipalResolver: goldenResolver{}, Authorizer: allowAuthorizer{}, Provider: goldenProvider{}})
	if err != nil {
		t.Fatalf("NewHandler(): %v", err)
	}
	return h
}

type goldenResolver struct{}

func (goldenResolver) CurrentPrincipal(*http.Request) (Principal, error) {
	return Principal{Subject: "user-1", Email: "admin@example.test", Role: "super_admin"}, nil
}

type errorResolver struct{ err error }

func (r errorResolver) CurrentPrincipal(*http.Request) (Principal, error) { return Principal{}, r.err }

type countingResolver struct{ calls int }

func (r *countingResolver) CurrentPrincipal(*http.Request) (Principal, error) {
	r.calls++
	return Principal{Subject: "user-1", Role: "super_admin"}, nil
}

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, Principal, string, string) error { return nil }

type errorAuthorizer struct{ err error }

func (a errorAuthorizer) Authorize(context.Context, Principal, string, string) error { return a.err }

type goldenProvider struct{}

func (goldenProvider) Capabilities(context.Context, Principal) (Capabilities, error) {
	return Capabilities{
		Module:       "authz",
		Provider:     "casbin",
		Capabilities: []string{"rbac"},
		Descriptors: []CapabilityDescriptor{{
			Mode: "rbac", Operations: []string{"check", "list"}, Configured: true, Source: "provider", Health: "ok",
		}},
		Health: "ok",
	}, nil
}

func (goldenProvider) RoleAssignments(context.Context, Principal) ([]RoleAssignment, error) {
	return []RoleAssignment{{User: "user-1", Role: "super_admin", Context: "admin", Scopes: []string{"admin:core-dump.authz:read"}}}, nil
}

func (goldenProvider) Policies(context.Context, Principal) ([]PolicyRule, error) {
	return []PolicyRule{{Subject: "super_admin", Object: "admin:status", Action: "read"}}, nil
}

func (goldenProvider) Decide(_ context.Context, principal Principal, request DecisionRequest) (Decision, error) {
	return Decision{Allowed: principal.Role == "super_admin" && request.Object == "admin:status" && request.Action == "read"}, nil
}

type errorProvider struct {
	goldenProvider
	err error
}

func (p errorProvider) Policies(context.Context, Principal) ([]PolicyRule, error) { return nil, p.err }

type nilCollectionProvider struct{ goldenProvider }

func (nilCollectionProvider) Capabilities(context.Context, Principal) (Capabilities, error) {
	return Capabilities{Module: "authz", Provider: "casbin", Health: "ok"}, nil
}

func (nilCollectionProvider) RoleAssignments(context.Context, Principal) ([]RoleAssignment, error) {
	return nil, nil
}

func (nilCollectionProvider) Policies(context.Context, Principal) ([]PolicyRule, error) {
	return nil, nil
}
