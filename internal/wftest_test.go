package internal_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow/wftest"
)

func TestWFTest_AddRemovePolicyPipeline(t *testing.T) {
	addRec := wftest.RecordStep("step.authz_add_policy")
	remRec := wftest.RecordStep("step.authz_remove_policy")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  policy-lifecycle:
    steps:
      - name: add_pol
        type: step.authz_add_policy
        config:
          module: authz
          rule: ["editor", "/docs/*", "write"]
      - name: rem_pol
        type: step.authz_remove_policy
        config:
          module: authz
          rule: ["editor", "/docs/*", "write"]
`),
		addRec.WithOutput(map[string]any{"added": true}),
		remRec.WithOutput(map[string]any{"removed": true}),
	)

	result := h.ExecutePipeline("policy-lifecycle", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if addRec.CallCount() != 1 {
		t.Errorf("expected authz_add_policy called once, got %d", addRec.CallCount())
	}
	if remRec.CallCount() != 1 {
		t.Errorf("expected authz_remove_policy called once, got %d", remRec.CallCount())
	}
	if result.StepResults["add_pol"]["added"] != true {
		t.Errorf("expected added=true, got %v", result.StepResults["add_pol"]["added"])
	}
	if result.StepResults["rem_pol"]["removed"] != true {
		t.Errorf("expected removed=true, got %v", result.StepResults["rem_pol"]["removed"])
	}
}

func TestWFTest_RoleAssignPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_role_assign")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  role-assign:
    steps:
      - name: assign
        type: step.authz_role_assign
        config:
          module: authz
          action: add
          assignments:
            - ["user-123", "admin"]
`),
		rec.WithOutput(map[string]any{"assigned": true, "count": 1}),
	)

	result := h.ExecutePipeline("role-assign", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_role_assign called once, got %d", rec.CallCount())
	}
	if result.StepResults["assign"]["assigned"] != true {
		t.Errorf("expected assigned=true, got %v", result.StepResults["assign"]["assigned"])
	}
}

func TestWFTest_ACLRevokePipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_acl_revoke")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  acl-revoke:
    steps:
      - name: revoke
        type: step.authz_acl_revoke
        config:
          module: authz
          subject: user-456
          object: /docs/report.pdf
          action: read
`),
		rec.WithOutput(map[string]any{"revoked": true}),
	)

	result := h.ExecutePipeline("acl-revoke", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_acl_revoke called once, got %d", rec.CallCount())
	}
	if result.StepResults["revoke"]["revoked"] != true {
		t.Errorf("expected revoked=true, got %v", result.StepResults["revoke"]["revoked"])
	}
}

func TestWFTest_ACLListPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_acl_list")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  acl-list:
    steps:
      - name: list
        type: step.authz_acl_list
        config:
          module: authz
          filter: subject
          value: user-789
`),
		rec.WithOutput(map[string]any{
			"entries": []any{
				map[string]any{"subject": "user-789", "object": "/api/data", "action": "read"},
			},
			"count": 1,
		}),
	)

	result := h.ExecutePipeline("acl-list", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_acl_list called once, got %d", rec.CallCount())
	}
	if result.StepResults["list"]["count"] != 1 {
		t.Errorf("expected count=1, got %v", result.StepResults["list"]["count"])
	}
}

func TestWFTest_ABACCheckPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_abac_check")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  abac-check:
    steps:
      - name: check
        type: step.authz_abac_check
        config:
          module: authz
          subject: alice
          object: document-42
          action: read
`),
		rec.WithOutput(map[string]any{
			"allowed": true,
			"subject": "alice",
			"object":  "document-42",
			"action":  "read",
		}),
	)

	result := h.ExecutePipeline("abac-check", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_abac_check called once, got %d", rec.CallCount())
	}
	if result.StepResults["check"]["allowed"] != true {
		t.Errorf("expected allowed=true, got %v", result.StepResults["check"]["allowed"])
	}
}

func TestWFTest_ABACAddPolicyPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_abac_add_policy")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  abac-add-policy:
    steps:
      - name: add_policy
        type: step.authz_abac_add_policy
        config:
          module: authz
          rule: ["engineering", "code-repo", "read"]
`),
		rec.WithOutput(map[string]any{"added": true}),
	)

	result := h.ExecutePipeline("abac-add-policy", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_abac_add_policy called once, got %d", rec.CallCount())
	}
	if result.StepResults["add_policy"]["added"] != true {
		t.Errorf("expected added=true, got %v", result.StepResults["add_policy"]["added"])
	}
}

func TestWFTest_ReBACAddRemoveRelationPipeline(t *testing.T) {
	addRec := wftest.RecordStep("step.authz_rebac_add_relation")
	remRec := wftest.RecordStep("step.authz_rebac_remove_relation")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  rebac-relation-lifecycle:
    steps:
      - name: add_rel
        type: step.authz_rebac_add_relation
        config:
          module: authz
          subject: user-123
          relation: owner
          object: document-42
      - name: rem_rel
        type: step.authz_rebac_remove_relation
        config:
          module: authz
          subject: user-123
          relation: owner
          object: document-42
`),
		addRec.WithOutput(map[string]any{"added": true}),
		remRec.WithOutput(map[string]any{"removed": true}),
	)

	result := h.ExecutePipeline("rebac-relation-lifecycle", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if addRec.CallCount() != 1 {
		t.Errorf("expected rebac_add_relation called once, got %d", addRec.CallCount())
	}
	if remRec.CallCount() != 1 {
		t.Errorf("expected rebac_remove_relation called once, got %d", remRec.CallCount())
	}
}

func TestWFTest_ReBACCheckPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_rebac_check")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  rebac-check:
    steps:
      - name: check
        type: step.authz_rebac_check
        config:
          module: authz
          subject: user-123
          object: document-42
          action: read
`),
		rec.WithOutput(map[string]any{"allowed": true}),
	)

	result := h.ExecutePipeline("rebac-check", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_rebac_check called once, got %d", rec.CallCount())
	}
	if result.StepResults["check"]["allowed"] != true {
		t.Errorf("expected allowed=true, got %v", result.StepResults["check"]["allowed"])
	}
}

func TestWFTest_ReBACListRelationsPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.authz_rebac_list_relations")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  rebac-list-relations:
    steps:
      - name: list_rels
        type: step.authz_rebac_list_relations
        config:
          module: authz
          filter: subject
          value: user-123
`),
		rec.WithOutput(map[string]any{
			"relations": []any{
				map[string]any{"object": "document-42", "relation": "owner"},
			},
			"count": 1,
		}),
	)

	result := h.ExecutePipeline("rebac-list-relations", nil)
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected authz_rebac_list_relations called once, got %d", rec.CallCount())
	}
	if result.StepResults["list_rels"]["count"] != 1 {
		t.Errorf("expected count=1, got %v", result.StepResults["list_rels"]["count"])
	}
}
