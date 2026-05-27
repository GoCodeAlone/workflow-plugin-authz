package internal

import (
	"context"
	"testing"
)

func TestCasbinCapabilities(t *testing.T) {
	mod := aclTestModule(t, nil)

	caps := mod.Capabilities()
	expected := map[AuthzCapability]bool{
		CapabilityACL: true,
	}
	if len(caps) != len(expected) {
		t.Fatalf("expected %d capabilities, got %d: %v", len(expected), len(caps), caps)
	}
	for _, c := range caps {
		if !expected[c] {
			t.Errorf("unexpected capability: %s", c)
		}
	}
}

func TestCasbinSupportsCapability(t *testing.T) {
	mod := aclTestModule(t, nil)

	for _, tc := range []struct {
		cap  AuthzCapability
		want bool
	}{
		{CapabilityRBAC, false},
		{CapabilityABAC, false},
		{CapabilityACL, true},
		{CapabilityReBAC, false},
	} {
		got := mod.SupportsCapability(tc.cap)
		if got != tc.want {
			t.Errorf("Casbin.SupportsCapability(%q): got %v, want %v", tc.cap, got, tc.want)
		}
	}
}

func TestCasbinCapabilitiesAreModelAware(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  *CasbinModule
		want map[AuthzCapability]bool
	}{
		{
			name: "acl",
			mod:  aclTestModule(t, nil),
			want: map[AuthzCapability]bool{CapabilityACL: true},
		},
		{
			name: "rbac",
			mod:  rbacTestModule(t, nil, nil),
			want: map[AuthzCapability]bool{CapabilityRBAC: true},
		},
		{
			name: "rebac",
			mod:  rebacTestModule(t),
			want: map[AuthzCapability]bool{CapabilityRBAC: true, CapabilityReBAC: true},
		},
		{
			name: "abac",
			mod:  abacAttributeTestModule(t),
			want: map[AuthzCapability]bool{CapabilityABAC: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilitySet(tc.mod.Capabilities())
			if len(got) != len(tc.want) {
				t.Fatalf("capabilities = %v, want %v", got, tc.want)
			}
			for capability := range tc.want {
				if !got[capability] {
					t.Fatalf("capability %q missing from %v", capability, got)
				}
			}
		})
	}
}

func TestPermitCapabilities(t *testing.T) {
	pm := &PermitModule{name: "test-permit"}

	caps := pm.Capabilities()
	expected := map[AuthzCapability]bool{
		CapabilityRBAC: true,
	}
	if len(caps) != len(expected) {
		t.Fatalf("expected %d capabilities, got %d: %v", len(expected), len(caps), caps)
	}
	for _, c := range caps {
		if !expected[c] {
			t.Errorf("unexpected capability: %s", c)
		}
	}
}

func TestPermitSupportsCapability(t *testing.T) {
	pm := &PermitModule{name: "test-permit"}

	for _, tc := range []struct {
		cap  AuthzCapability
		want bool
	}{
		{CapabilityRBAC, true},
		{CapabilityABAC, false},
		{CapabilityReBAC, false},
		{CapabilityACL, false},
	} {
		got := pm.SupportsCapability(tc.cap)
		if got != tc.want {
			t.Errorf("Permit.SupportsCapability(%q): got %v, want %v", tc.cap, got, tc.want)
		}
	}
}

func TestKetoCapabilities(t *testing.T) {
	km := &KetoModule{name: "test-keto"}
	got := capabilitySet(km.Capabilities())
	want := map[AuthzCapability]bool{
		CapabilityRBAC:  true,
		CapabilityReBAC: true,
	}
	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	for capability := range want {
		if !got[capability] {
			t.Fatalf("capability %q missing from %v", capability, got)
		}
	}
	if km.SupportsCapability(CapabilityABAC) {
		t.Fatal("keto should not claim ABAC support")
	}
}

func TestAuthzCapabilitiesStep_Casbin(t *testing.T) {
	mod := aclTestModule(t, nil)
	reg := &testRegistry{mod: mod}

	s, err := newAuthzCapabilitiesStep("caps", map[string]any{
		"provider": "casbin",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if result.Output["provider"] != "casbin" {
		t.Errorf("expected provider=casbin, got %v", result.Output["provider"])
	}

	caps, ok := result.Output["capabilities"].([]any)
	if !ok {
		t.Fatalf("expected capabilities to be []any, got %T", result.Output["capabilities"])
	}
	if len(caps) != 1 {
		t.Errorf("expected 1 capability for casbin ACL model, got %d", len(caps))
	}

	capSet := make(map[string]bool)
	for _, c := range caps {
		capSet[c.(string)] = true
	}
	for _, expected := range []string{"acl"} {
		if !capSet[expected] {
			t.Errorf("expected capability %q in output", expected)
		}
	}
}

func TestAuthzCapabilitiesStep_Permit(t *testing.T) {
	// Register a fake permit client so the step can find it
	RegisterPermitClient("test-permit", &permitClient{})
	defer UnregisterPermitClient("test-permit")

	s, err := newAuthzCapabilitiesStep("caps", map[string]any{
		"module":   "test-permit",
		"provider": "permit",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if result.Output["provider"] != "permit" {
		t.Errorf("expected provider=permit, got %v", result.Output["provider"])
	}

	caps, ok := result.Output["capabilities"].([]any)
	if !ok {
		t.Fatalf("expected capabilities to be []any, got %T", result.Output["capabilities"])
	}
	if len(caps) != 1 {
		t.Errorf("expected 1 implemented capability for permit, got %d", len(caps))
	}

	capSet := make(map[string]bool)
	for _, c := range caps {
		capSet[c.(string)] = true
	}
	if !capSet["rbac"] {
		t.Error("expected rbac capability in output")
	}
	for _, unsupported := range []string{"abac", "rebac"} {
		if capSet[unsupported] {
			t.Errorf("permit step should not advertise unimplemented capability %q", unsupported)
		}
	}
}

func TestAuthzCapabilitiesStep_Keto(t *testing.T) {
	reg := &testCapabilityRegistry{providers: map[string]AuthzProvider{
		"test-keto": &KetoModule{name: "test-keto"},
	}}
	s, err := newAuthzCapabilitiesStep("caps", map[string]any{
		"module":   "test-keto",
		"provider": "keto",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}
	s.registry = reg

	result, err := s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	caps := result.Output["capabilities"].([]any)
	capSet := make(map[string]bool)
	for _, c := range caps {
		capSet[c.(string)] = true
	}
	for _, expected := range []string{"rbac", "rebac"} {
		if !capSet[expected] {
			t.Errorf("expected capability %q in output", expected)
		}
	}
	if capSet["abac"] {
		t.Error("keto capabilities should not include abac")
	}
}

func TestAuthzCapabilityDescriptorsAreTruthful(t *testing.T) {
	reg := &testCapabilityRegistry{mod: rebacTestModule(t), providers: map[string]AuthzProvider{
		"keto": &KetoModule{name: "keto"},
	}}
	for _, tc := range []struct {
		name        string
		module      string
		provider    string
		wantModes   []string
		wantOps     map[string][]string
		rejectModes []string
	}{
		{
			name:      "casbin rebac model",
			module:    "authz",
			provider:  "casbin",
			wantModes: []string{"rbac", "rebac"},
			wantOps: map[string][]string{
				"rbac":  {"check", "manage_roles"},
				"rebac": {"check", "manage_relations", "list"},
			},
			rejectModes: []string{"abac", "acl"},
		},
		{
			name:      "keto",
			module:    "keto",
			provider:  "keto",
			wantModes: []string{"rbac", "rebac"},
			wantOps: map[string][]string{
				"rbac":  {"check", "manage_roles"},
				"rebac": {"check", "manage_relations"},
			},
			rejectModes: []string{"abac", "acl"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step, err := newAuthzCapabilitiesStep("caps", map[string]any{
				"module":   tc.module,
				"provider": tc.provider,
			})
			if err != nil {
				t.Fatalf("newAuthzCapabilitiesStep: %v", err)
			}
			step.registry = reg
			result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			descriptors := capabilityDescriptorMaps(t, result.Output["capability_descriptors"])
			byMode := make(map[string]map[string]any, len(descriptors))
			for _, descriptor := range descriptors {
				mode := descriptor["mode"].(string)
				byMode[mode] = descriptor
				if descriptor["configured"] != true {
					t.Fatalf("%s configured = %v, want true", mode, descriptor["configured"])
				}
				if descriptor["source"] == "" {
					t.Fatalf("%s missing source", mode)
				}
				if descriptor["health"] != "ok" {
					t.Fatalf("%s health = %v, want ok", mode, descriptor["health"])
				}
				if descriptor["unsupported_reason"] != "" {
					t.Fatalf("%s unsupported_reason = %v, want empty", mode, descriptor["unsupported_reason"])
				}
			}
			for _, mode := range tc.wantModes {
				descriptor, ok := byMode[mode]
				if !ok {
					t.Fatalf("missing descriptor for %q in %#v", mode, descriptors)
				}
				gotOps := stringSet(stringSliceValue(descriptor["operations"]))
				for _, op := range tc.wantOps[mode] {
					if !gotOps[op] {
						t.Fatalf("%s missing operation %q in %v", mode, op, gotOps)
					}
				}
			}
			for _, mode := range tc.rejectModes {
				if _, ok := byMode[mode]; ok {
					t.Fatalf("descriptor should not advertise unsupported mode %q", mode)
				}
			}
		})
	}
}

func TestAuthzProviderRequireCapabilitiesFailsClosed(t *testing.T) {
	var provider AuthzProvider = &KetoModule{name: "keto"}
	err := provider.RequireCapabilities([]CapabilityRequirement{{
		Mode:       CapabilityABAC,
		Operations: []AuthzOperation{OperationCheck},
	}})
	if err == nil {
		t.Fatal("expected Keto to reject ABAC requirement")
	}
}

func TestAuthzCapabilitiesStep_UnknownProvider(t *testing.T) {
	s, err := newAuthzCapabilitiesStep("bad", map[string]any{
		"provider": "unknown",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestAuthzCapabilitiesStep_CasbinModuleNotFound(t *testing.T) {
	reg := &testRegistry{} // no module
	s, err := newAuthzCapabilitiesStep("no-mod", map[string]any{
		"provider": "casbin",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}
	s.registry = reg

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when casbin module not found")
	}
}

func TestAuthzCapabilitiesStep_PermitModuleNotFound(t *testing.T) {
	s, err := newAuthzCapabilitiesStep("no-mod", map[string]any{
		"module":   "nonexistent",
		"provider": "permit",
	})
	if err != nil {
		t.Fatalf("newAuthzCapabilitiesStep: %v", err)
	}

	_, err = s.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err == nil {
		t.Error("expected error when permit module not found")
	}
}

// --- Integration: same flow across RBAC and ACL ---

func TestIntegration_RBAC_And_ACL_SameFlow(t *testing.T) {
	// Test that the same user/resource/action flow works across both models.
	// RBAC: alice has admin role -> admin can GET /api
	rbacMod := rbacTestModule(t,
		[][]string{{"admin", "/api", "GET"}},
		[][]string{{"alice", "admin"}},
	)
	rbacReg := &testRegistry{mod: rbacMod}

	// ACL: alice directly has GET /api
	aclMod := aclTestModule(t, [][]string{{"alice", "/api", "GET"}})
	aclReg := &testRegistry{mod: aclMod}

	// Check via RBAC
	rbacCheck := newTestStep(t, map[string]any{
		"object": "/api",
		"action": "GET",
	}, rbacReg)
	rbacAllowed, rbacStopped := execute(t, rbacCheck, nil,
		map[string]any{"auth_user_id": "alice"}, nil)
	if !rbacAllowed || rbacStopped {
		t.Errorf("RBAC: expected alice allowed; got allowed=%v stopped=%v", rbacAllowed, rbacStopped)
	}

	// Check via ACL
	aclCheckStep, err := newAuthzACLCheckStep("acl-check", map[string]any{
		"subject": "alice",
		"object":  "/api",
		"action":  "GET",
	})
	if err != nil {
		t.Fatalf("newAuthzACLCheckStep: %v", err)
	}
	aclCheckStep.registry = aclReg

	result, err := aclCheckStep.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("ACL check: %v", err)
	}
	if result.Output["allowed"] != true {
		t.Error("ACL: expected alice allowed GET /api")
	}
}

func TestIntegration_UnsupportedCapability_ClearError(t *testing.T) {
	mod := aclTestModule(t, nil)

	// Casbin does not support ReBAC
	if mod.SupportsCapability(CapabilityReBAC) {
		t.Error("Casbin should not support ReBAC capability")
	}

	// Permit does not support ACL
	pm := &PermitModule{name: "test"}
	if pm.SupportsCapability(CapabilityACL) {
		t.Error("Permit should not support ACL capability")
	}
}

func abacAttributeTestModule(t *testing.T) *CasbinModule {
	t.Helper()
	m, err := newCasbinModule("authz", map[string]any{
		"model": `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_department, obj_kind, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub.department == p.sub_department && r.obj.kind == p.obj_kind && r.act == p.act
`,
	})
	if err != nil {
		t.Fatalf("newCasbinModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return m
}

func capabilitySet(capabilities []AuthzCapability) map[AuthzCapability]bool {
	out := make(map[AuthzCapability]bool, len(capabilities))
	for _, capability := range capabilities {
		out[capability] = true
	}
	return out
}

func capabilityDescriptorMaps(t *testing.T, value any) []map[string]any {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("expected capability_descriptors to be []any, got %T", value)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("expected descriptor map, got %T", item)
		}
		out = append(out, m)
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

type testCapabilityRegistry struct {
	mod       *CasbinModule
	providers map[string]AuthzProvider
}

func (r *testCapabilityRegistry) GetEnforcer(name string) (*CasbinModule, bool) {
	if r.mod != nil && r.mod.name == name {
		return r.mod, true
	}
	return nil, false
}

func (r *testCapabilityRegistry) GetAuthzProvider(name string) (AuthzProvider, bool) {
	provider, ok := r.providers[name]
	return provider, ok
}
