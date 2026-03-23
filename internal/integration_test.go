package internal_test

import (
	"testing"

	authzplugin "github.com/GoCodeAlone/workflow-plugin-authz/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"github.com/GoCodeAlone/workflow/wftest"
)

func TestIntegration_AuthzCheckPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_check_casbin")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  authz-check:
    steps:
      - name: check
        type: step.authz_check_casbin
        config:
          module: authz
          subject_key: auth_user_id
          object: /api/v1/resources
          action: GET
`),
		rec.WithOutput(map[string]any{
			"authz_allowed": true,
			"authz_subject": "user-123",
			"authz_object":  "/api/v1/resources",
			"authz_action":  "GET",
		}),
	)

	result := h.ExecutePipeline("authz-check", map[string]any{"auth_user_id": "user-123"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_check_casbin called once, got %d", rec.CallCount())
	}
	if result.StepResults["check"]["authz_allowed"] != true {
		t.Errorf("expected authz_allowed=true, got %v", result.StepResults["check"]["authz_allowed"])
	}
}

func TestIntegration_ACLGrantAndCheckPipeline(t *testing.T) {
	grantRec := wftest.RecordStep("step.authz_acl_grant")
	checkRec := wftest.RecordStep("step.authz_acl_check")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  acl-flow:
    steps:
      - name: grant
        type: step.authz_acl_grant
        config:
          module: authz
          subject_key: user_id
          resource: /docs/report.pdf
          permission: read
      - name: check
        type: step.authz_acl_check
        config:
          module: authz
          subject_key: user_id
          resource: /docs/report.pdf
          permission: read
`),
		grantRec.WithOutput(map[string]any{"granted": true}),
		checkRec.WithOutput(map[string]any{"allowed": true}),
	)

	result := h.ExecutePipeline("acl-flow", map[string]any{"user_id": "user-456"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if grantRec.CallCount() != 1 {
		t.Errorf("expected acl_grant called once, got %d", grantRec.CallCount())
	}
	if result.StepResults["check"]["allowed"] != true {
		t.Errorf("expected allowed=true, got %v", result.StepResults["check"]["allowed"])
	}
}

func TestIntegration_CapabilitiesPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_capabilities")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  capabilities:
    steps:
      - name: caps
        type: step.authz_capabilities
        config:
          module: authz
          subject_key: auth_user_id
`),
		rec.WithOutput(map[string]any{
			"capabilities": []any{"read", "write"},
			"count":        2,
		}),
	)

	result := h.ExecutePipeline("capabilities", map[string]any{"auth_user_id": "user-789"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_capabilities called once, got %d", rec.CallCount())
	}
	if result.StepResults["caps"]["count"] != 2 {
		t.Errorf("expected count=2, got %v", result.StepResults["caps"]["count"])
	}
}

func TestIntegration_PluginManifestAndStepTypes(t *testing.T) {
	p := authzplugin.NewAuthzPlugin()
	m := p.Manifest()
	if m.Name != "workflow-plugin-authz" {
		t.Errorf("unexpected plugin name: %s", m.Name)
	}

	sp, ok := p.(sdk.StepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.StepProvider")
	}

	if len(sp.StepTypes()) == 0 {
		t.Error("expected at least one step type")
	}
}
