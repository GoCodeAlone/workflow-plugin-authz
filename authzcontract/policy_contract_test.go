package authzcontract

import "testing"

func TestPublicCasbinPolicyContractNormalizesPluginWrapper(t *testing.T) {
	got, err := NormalizeCasbinPolicyConfig(CasbinPolicyConfig{
		Type:          CasbinModuleType,
		DefaultEffect: EffectDeny,
		Policies: [][]string{
			{"dashboard-admin", "/v1/dashboard/*", "GET"},
		},
		RoleAssignmentsCamel: [][]string{
			{"alice", "dashboard-admin"},
		},
		Config: &CasbinPolicyConfig{
			Model:         "workflow-compute-rbac",
			DefaultEffect: "",
			Policies: [][]string{
				{"operator", "/v1/provider-contracts", "POST", EffectAllow},
			},
			RoleAssignments: [][]string{
				{"bob", "operator"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeCasbinPolicyConfig: %v", err)
	}
	if got.Type != CasbinModuleType {
		t.Fatalf("Type=%q, want %q", got.Type, CasbinModuleType)
	}
	if got.Config != nil {
		t.Fatalf("Config should be flattened after normalization: %+v", got.Config)
	}
	if got.Model != "workflow-compute-rbac" {
		t.Fatalf("Model=%q", got.Model)
	}
	if got.DefaultEffect != EffectDeny {
		t.Fatalf("DefaultEffect=%q, want %q", got.DefaultEffect, EffectDeny)
	}
	if len(got.Policies) != 2 {
		t.Fatalf("Policies=%+v, want parent and nested policies", got.Policies)
	}
	if len(got.RoleAssignments) != 2 {
		t.Fatalf("RoleAssignments=%+v, want camel and nested role assignments", got.RoleAssignments)
	}
}

func TestPublicCasbinPolicyContractRejectsUnsupportedType(t *testing.T) {
	_, err := NormalizeCasbinPolicyConfig(CasbinPolicyConfig{Type: "authz.other"})
	if err == nil {
		t.Fatal("expected unsupported policy type to fail")
	}
}

func TestPublicCasbinPolicyContractNestedConfigOverridesWrapperDefaultEffect(t *testing.T) {
	got, err := NormalizeCasbinPolicyConfig(CasbinPolicyConfig{
		DefaultEffect: EffectAllow,
		Config: &CasbinPolicyConfig{
			DefaultEffect: EffectDeny,
		},
	})
	if err != nil {
		t.Fatalf("NormalizeCasbinPolicyConfig: %v", err)
	}
	if got.DefaultEffect != EffectDeny {
		t.Fatalf("DefaultEffect=%q, want nested %q", got.DefaultEffect, EffectDeny)
	}
}
