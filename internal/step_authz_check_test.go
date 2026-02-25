package internal

import (
	"context"
	"testing"
)

// --- test registry ---

// testRegistry is a simple mock that returns a fixed CasbinModule.
type testRegistry struct {
	mod *CasbinModule
}

func (r *testRegistry) GetEnforcer(name string) (*CasbinModule, bool) {
	if r.mod != nil && r.mod.name == name {
		return r.mod, true
	}
	return nil, false
}

// defaultTestModule builds and initialises an authz.casbin module with a
// standard RBAC model using keyMatch2 for path matching.
func defaultTestModule(t *testing.T) *CasbinModule {
	t.Helper()
	cfg := map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (keyMatch2(r.obj, p.obj) || r.obj == p.obj) && (r.act == p.act || p.act == "*")
`,
		"policies": []any{
			[]any{"admin", "/api/*", "*"},
			[]any{"editor", "/api/posts", "GET"},
			[]any{"editor", "/api/posts", "POST"},
			[]any{"viewer", "/api/posts", "GET"},
		},
		"roleAssignments": []any{
			[]any{"alice", "admin"},
			[]any{"bob", "editor"},
			[]any{"carol", "viewer"},
		},
	}
	m, err := newCasbinModule("authz", cfg)
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("CasbinModule.Init: %v", err)
	}
	return m
}

// newTestStep creates an authzCheckStep wired to the given registry.
func newTestStep(t *testing.T, config map[string]any, reg moduleRegistry) *authzCheckStep {
	t.Helper()
	s, err := newAuthzCheckStep("test-step", config)
	if err != nil {
		t.Fatalf("newAuthzCheckStep: %v", err)
	}
	s.registry = reg
	return s
}

// execute is a convenience wrapper for authzCheckStep.Execute.
func execute(t *testing.T, s *authzCheckStep, triggerData, current map[string]any, stepOutputs map[string]map[string]any) (allowed bool, stopped bool) {
	t.Helper()
	if triggerData == nil {
		triggerData = map[string]any{}
	}
	if current == nil {
		current = map[string]any{}
	}
	if stepOutputs == nil {
		stepOutputs = map[string]map[string]any{}
	}
	result, err := s.Execute(context.Background(), triggerData, stepOutputs, current, nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if result == nil {
		t.Fatal("Execute returned nil result")
	}
	a, _ := result.Output["authz_allowed"].(bool)
	return a, result.StopPipeline
}

// --- tests ---

func TestAuthzCheckStep_AllowAdmin(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "DELETE",
	}, reg)

	// alice is assigned admin role → admin policy covers /api/* with *
	allowed, stopped := execute(t, s,
		nil,
		map[string]any{"auth_user_id": "alice"},
		nil,
	)
	if !allowed || stopped {
		t.Errorf("expected admin alice to be allowed; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_AllowEditor(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "POST",
	}, reg)

	// bob is assigned editor → editor can POST /api/posts
	allowed, stopped := execute(t, s,
		nil,
		map[string]any{"auth_user_id": "bob"},
		nil,
	)
	if !allowed || stopped {
		t.Errorf("expected editor bob to be allowed; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_DenyViewer(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "DELETE",
	}, reg)

	// carol is viewer → viewer cannot DELETE
	allowed, stopped := execute(t, s,
		nil,
		map[string]any{"auth_user_id": "carol"},
		nil,
	)
	if allowed || !stopped {
		t.Errorf("expected viewer carol to be denied; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_DenyUnknownUser(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "GET",
	}, reg)

	// "dave" has no role assignments → denied
	allowed, stopped := execute(t, s,
		nil,
		map[string]any{"auth_user_id": "dave"},
		nil,
	)
	if allowed || !stopped {
		t.Errorf("expected unknown user to be denied; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_MissingSubject(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "GET",
	}, reg)

	// No auth_user_id in any context → forbidden with stop
	allowed, stopped := execute(t, s, nil, nil, nil)
	if allowed || !stopped {
		t.Errorf("expected missing subject to be denied; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_SubjectFromStepOutputs(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "GET",
	}, reg)

	// auth_user_id injected by a prior step (step.auth_required pattern)
	allowed, stopped := execute(t, s,
		nil,
		nil,
		map[string]map[string]any{
			"step0": {"auth_user_id": "alice"},
		},
	)
	if !allowed || stopped {
		t.Errorf("expected alice (from step outputs) to be allowed; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_TemplateObject(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "{{.request_path}}",
		"action": "GET",
	}, reg)

	// viewer carol → GET /api/posts (via template)
	allowed, stopped := execute(t, s,
		map[string]any{"request_path": "/api/posts"},
		map[string]any{"auth_user_id": "carol"},
		nil,
	)
	if !allowed || stopped {
		t.Errorf("expected carol to be allowed GET /api/posts via template; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_TemplateAction(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "{{.request_method}}",
	}, reg)

	// alice admin DELETE via template
	allowed, stopped := execute(t, s,
		map[string]any{"request_method": "DELETE"},
		map[string]any{"auth_user_id": "alice"},
		nil,
	)
	if !allowed || stopped {
		t.Errorf("expected alice DELETE via template; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_CustomSubjectKey(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"subject_key": "auth_email",
		"object":      "/api/posts",
		"action":      "GET",
	}, reg)

	// Register alice by email in policy — reuse same module but with email as subject
	// The default module policies use usernames not emails, so this should deny.
	// (alice's email is not a direct policy subject.)
	allowed, stopped := execute(t, s,
		nil,
		map[string]any{"auth_email": "alice@example.com"},
		nil,
	)
	// alice@example.com has no policy → denied
	if allowed || !stopped {
		t.Errorf("expected alice@example.com (unmapped) to be denied; got allowed=%v stopped=%v", allowed, stopped)
	}
}

func TestAuthzCheckStep_MissingObject(t *testing.T) {
	_, err := newAuthzCheckStep("s", map[string]any{"action": "GET"})
	if err == nil {
		t.Error("expected error for missing object config")
	}
}

func TestAuthzCheckStep_MissingAction(t *testing.T) {
	_, err := newAuthzCheckStep("s", map[string]any{"object": "/api/foo"})
	if err == nil {
		t.Error("expected error for missing action config")
	}
}

func TestAuthzCheckStep_ModuleNotFound(t *testing.T) {
	reg := &testRegistry{} // no module registered

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "GET",
	}, reg)

	_, err := s.Execute(context.Background(),
		nil,
		nil,
		map[string]any{"auth_user_id": "alice"},
		nil,
	)
	if err == nil {
		t.Error("expected error when module not found")
	}
}

func TestAuthzCheckStep_403ResponseFields(t *testing.T) {
	mod := defaultTestModule(t)
	reg := &testRegistry{mod: mod}

	s := newTestStep(t, map[string]any{
		"object": "/api/posts",
		"action": "DELETE",
	}, reg)

	result, err := s.Execute(context.Background(),
		nil,
		nil,
		map[string]any{"auth_user_id": "carol"},
		nil,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline {
		t.Error("expected StopPipeline=true on deny")
	}
	if status, _ := result.Output["response_status"].(int); status != 403 {
		t.Errorf("expected response_status=403, got %v", result.Output["response_status"])
	}
	if body, _ := result.Output["response_body"].(string); body == "" {
		t.Error("expected non-empty response_body")
	}
}
