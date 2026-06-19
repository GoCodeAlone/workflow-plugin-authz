# Authz Modes Admin Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Implement truthful RBAC/ABAC/ReBAC capability discovery, provider-native management contracts, capability-driven admin UI, YAML/Go/SPA enforcement surfaces, and a refreshed demo with exploratory QA.

**Architecture:** `workflow-plugin-authz` owns strict provider contracts and enforcement APIs. `workflow-plugin-authz-ui` renders capability-aware management surfaces from lookup-backed catalogs. `workflow-scenarios` proves app/admin/provider behavior with local Casbin/Keto and env-gated Permit live tests.

**Tech Stack:** Go, protobuf strict contracts, Workflow plugin SDK, React/Vite/TypeScript, Docker Compose, Ory Keto, Permit Go SDK, Casbin, Playwright.

**Base branch:** `workflow-plugin-authz/main`; related branches in `workflow-plugin-authz-ui` and `workflow-scenarios`.

---

## Scope Manifest

**PR Count:** 4
**Tasks:** 12
**Estimated Lines of Change:** ~4500

**Out of scope:**
- Adding Permify as a provider in this implementation.
- Replacing authn provider/session implementation.
- Production deploy or production Permit project mutation without explicit env-backed test approval.
- Engine ABI changes outside plugin-owned contracts.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Authz provider contracts and enforcement | Task 1, Task 2, Task 3, Task 4, Task 5 | feat/authz-modes-core |
| 2 | Capability-driven authz admin UI | Task 6, Task 7, Task 8, Task 9, Task 10 | feat/authz-modes-ui |
| 3 | Scenario demo and provider rotation | Task 11 | feat/authz-modes-demo |
| 4 | Integration, exploratory QA, security review | Task 12 | feat/authz-modes-validation |

**Status:** Complete 2026-06-19T23:22:00Z

**Closeout evidence:** Current `main` includes the released authz provider/admin integration work. Cleanup verification on 2026-06-19: `GOWORK=off go test ./...` and `wfctl plugin validate-contract .` both passed.

## Preflight Already Completed

- Capability bug fixed in `f6ec8f3`: Casbin reports model-aware capabilities; Keto reports RBAC/ReBAC; `step.authz_capabilities` can resolve Keto providers.
- Design committed in `docs/plans/2026-05-27-authz-modes-admin-design.md`.
- Design adversarial review PASS after replacing engine-level `modules[].requires` with authz-owned config/typed step.

### Task 1: Provider Capability Descriptors

**Files:**
- Modify: `internal/contracts/authz.proto`
- Modify: `internal/contracts/authz.pb.go`
- Modify: `internal/capabilities.go`
- Modify: `internal/capabilities_test.go`
- Modify: `internal/plugin.go`
- Test: `internal/plugin_contracts_test.go`

**Steps:**
1. Write failing tests for structured capability output: modes, operations, configured flag, source (`detected|declared|provider`), health, unsupported reasons.
2. Run `GOWORK=off go test ./internal -run 'TestCapabilityDescriptor|TestAuthzCapabilitiesStep'`; expect missing proto/fields.
3. Extend proto with `AuthzMode`, `AuthzOperation`, `CapabilityDescriptor`, `ProviderCapabilitiesInput/Output`, `CapabilityRequirement`.
4. Replace string-only output with descriptor output while preserving legacy `capabilities: []string` for compatibility.
5. Add provider health/degraded state without secrets.
6. Add typed service contracts for `ProviderCapabilities.GetCapabilities` and `ProviderCapabilities.RequireCapabilities`.
7. Regenerate protobufs with repo-local generation command.
8. Run focused tests and contract validation.

**Verification:** `GOWORK=off go test ./internal -run 'TestCapabilityDescriptor|TestAuthzCapabilitiesStep|TestPluginImplementsStrictContractProviders' && wfctl plugin validate-contract .` → PASS.

**Rollback:** Revert Task 1 commit; legacy string capabilities remain from preflight fix.

### Task 2: Authz Declaration Catalog

**Files:**
- Modify: `internal/contracts/authz.proto`
- Modify: `internal/contracts/authz.pb.go`
- Modify: `internal/module_scope_catalog.go`
- Modify: `internal/scope_catalog_test.go`
- Create: `internal/authz_declarations.go`
- Create: `internal/authz_declarations_test.go`

**Steps:**
1. Write failing tests for plugin-owned declarations: resources/actions, scopes, attributes, relation types, UI actions.
2. Run focused tests; expect missing types.
3. Add proto messages: `ResourceDeclaration`, `ActionDeclaration`, `AttributeDeclaration`, `AttributeValue`, `RelationDeclaration`, `UIActionDeclaration`, `AuthzDeclarationSet`.
4. Extend scope catalog into an authz declaration catalog while preserving existing scope APIs.
5. Validate names, contexts, owner plugin/module, data types, allowed values, lookup source IDs.
6. Add service methods `RegisterDeclarations`, `ListDeclarations`, `ResolveProjectionInputs`.
7. Add tests that third-party plugin declarations are provider-neutral.

**Verification:** `GOWORK=off go test ./internal -run 'TestAuthzDeclarations|TestScopeCatalog' && wfctl plugin validate-contract .` → PASS.

**Rollback:** Revert Task 2 commit; scope catalog APIs remain.

### Task 3: ABAC Provider Contract

**Files:**
- Modify: `internal/contracts/authz.proto`
- Modify: `internal/capabilities.go`
- Modify: `internal/step_abac.go`
- Modify: `internal/step_abac_test.go`
- Create: `internal/abac_provider.go`
- Create: `internal/abac_provider_test.go`
- Modify: `internal/provider_permit.go`
- Modify: `internal/module_casbin.go`

**Steps:**
1. Write failing conformance tests for `AttributePolicyProvider`: declare attributes, upsert/list/remove policy, check with subject/resource/environment attrs.
2. Add proto messages: `AttributePolicy`, `AttributeCondition`, `AttributeCheckInput/Output`, `UpsertAttributePolicy*`, `ListAttributePolicies*`, `RemoveAttributePolicy*`.
3. Implement in-memory conformance store used by Casbin tests and Permit fake SDK tests.
4. Implement Casbin ABAC adapter only when loaded model supports ABAC; otherwise return unsupported.
5. Implement Permit ABAC adapter only for SDK-backed surfaces actually wired; unsupported operations return typed unsupported errors and are not advertised.
6. Add provider capability descriptors that show ABAC operations only when implemented/configured.
7. Add fail-closed checks for malformed attrs, unknown attrs, and provider errors.

**Verification:** `GOWORK=off go test ./internal -run 'TestABACProvider|TestABAC|TestCapabilityDescriptor'` → PASS with explicit unsupported tests.

**Rollback:** Revert Task 3 commit; RBAC/ReBAC contracts remain.

### Task 4: ReBAC Provider Contract

**Files:**
- Modify: `internal/contracts/authz.proto`
- Modify: `internal/provider_keto.go`
- Modify: `internal/provider_keto_test.go`
- Modify: `internal/provider_permit.go`
- Modify: `internal/step_rebac.go`
- Modify: `internal/step_rebac_test.go`
- Create: `internal/rebac_provider.go`
- Create: `internal/rebac_provider_test.go`

**Steps:**
1. Write failing conformance tests for relation schema, tuple upsert/delete/list, relationship check, and graph lookup.
2. Add proto messages: `RelationTuple`, `RelationCheckInput/Output`, `UpsertRelationTuple*`, `ListRelationTuples*`, `RemoveRelationTuple*`.
3. Implement Keto relationship provider using official SDK tuple APIs.
4. Implement Casbin ReBAC adapter only for models with `g2`; unsupported otherwise.
5. Implement Permit ReBAC adapter only for SDK surfaces actually wired; no claims for unwired operations.
6. Add tuple validation against relation/resource declarations.
7. Add removal tests proving deselect/delete changes enforcement.

**Verification:** `GOWORK=off go test ./internal -run 'TestReBACProvider|TestKetoProvider|TestReBAC'` → PASS.

**Rollback:** Revert Task 4 commit; existing Keto scope-role provider remains.

### Task 5: Unified Decision API and YAML Steps

**Files:**
- Modify: `internal/contracts/authz.proto`
- Modify: `internal/plugin.go`
- Modify: `internal/typed.go`
- Create: `internal/decision_provider.go`
- Create: `internal/decision_provider_test.go`
- Create: `internal/step_authz_decision.go`
- Create: `internal/step_authz_decision_test.go`
- Modify: `README.md`

**Steps:**
1. Write failing tests for `step.authz_check`, `step.authz_require_capabilities`, RBAC/ABAC/ReBAC mode-specific typed steps.
2. Add unified `AuthorizationDecisionInput/Output` with provider, mode preference, subject, context, resource, action, scope, attrs, relation hint, explain.
3. Implement routing to provider-native RBAC/ABAC/ReBAC checks based on capability descriptors and request shape.
4. Implement explicit unsupported and ambiguous-mode errors.
5. Add YAML examples for route gating, workflow action gating, and startup capability requirements.
6. Add Go service examples for module code invoking decision provider.

**Verification:** `GOWORK=off go test ./internal -run 'TestAuthorizationDecision|TestAuthzDecisionStep|TestTypedProviders' && wfctl plugin validate-contract .` → PASS.

**Rollback:** Revert Task 5 commit; mode-native contracts remain.

### Task 6: UI Runtime Capability Client

**Files:**
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/api.ts`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/types.ts`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/App.tsx`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/test/source-contract.test.mjs`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/internal/contracts/authz_ui.proto`

**Steps:**
1. Write failing UI source tests for capability fetch, hidden unsupported tabs, and lookup-driven config.
2. Extend runtime config with capabilities endpoint, projection endpoint, and declaration catalog endpoint.
3. Add typed TS models for capability descriptors and declarations.
4. Refactor app shell to render `Overview`, `RBAC`, `ABAC`, `ReBAC`, `Simulator`, `Audit` based on descriptors.
5. Add disabled Overview states for unsupported/unavailable modes.
6. Keep base path configurable.

**Verification:** `cd /Users/jon/workspace/workflow-plugin-authz-ui/ui && npm test && npm run build && npm run lint` → PASS.

**Rollback:** Revert Task 6 commit; old RBAC screen remains.

### Task 7: RBAC UI Lookup UX

**Files:**
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/RoleTable.tsx`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/styles/index.css`
- Test: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/test/source-contract.test.mjs`

**Steps:**
1. Write failing tests that no RBAC scope/user/resource/action form uses free-text when lookup data exists.
2. Add role scope select/deselect with persisted remove assignment flow.
3. Add user/group lookup, role lookup, scope lookup, context filter, and selected chips.
4. Add explicit enforcement simulator entry from selected role/user.
5. Verify deselect removes scope and subsequent check denies.

**Verification:** UI tests/build/lint PASS; Playwright later checks checkbox/select/deselect behavior in running demo.

**Rollback:** Revert Task 7 commit; Task 6 shell still renders.

### Task 8: ABAC UI

**Files:**
- Create: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/ABACPolicyTable.tsx`
- Create: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/AttributeConditionEditor.tsx`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/api.ts`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/styles/index.css`
- Test: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/test/source-contract.test.mjs`

**Steps:**
1. Write failing source tests for ABAC tab, attribute lookup, operator lookup, no arbitrary text for declared enums.
2. Implement policy list/upsert/delete forms using attribute declarations.
3. Add condition builder with type-aware controls: enum select, boolean toggle, numeric input, string input only if schema permits custom.
4. Add ABAC simulator panel with subject/resource/environment attrs.
5. Hide tab if provider lacks `abac/check`.

**Verification:** `npm test && npm run build && npm run lint` → PASS; scenario/Playwright later confirms runtime.

**Rollback:** Revert Task 8 commit; shell hides ABAC if unsupported.

### Task 9: ReBAC UI

**Files:**
- Create: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/ReBACTupleTable.tsx`
- Create: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/RelationPicker.tsx`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/api.ts`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/styles/index.css`
- Test: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/test/source-contract.test.mjs`

**Steps:**
1. Write failing source tests for relation tuple tab and lookup-backed subject/relation/object selectors.
2. Implement tuple list/upsert/delete.
3. Add resource type filter and relation dropdown sourced from declarations.
4. Add relation check simulator.
5. Add graph-adjacent table showing subject → relation → object without decorative graph complexity.
6. Hide tab if provider lacks `rebac/check`.

**Verification:** `npm test && npm run build && npm run lint` → PASS; scenario/Playwright later confirms runtime.

**Rollback:** Revert Task 9 commit; shell hides ReBAC if unsupported.

### Task 10: SPA Projection and Admin Contribution Authz

**Files:**
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/api.ts`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/types.ts`
- Create: `/Users/jon/workspace/workflow-plugin-authz-ui/ui/src/components/ProjectionPreview.tsx`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/internal/module.go`
- Modify: `/Users/jon/workspace/workflow-plugin-authz-ui/internal/plugin_test.go`

**Steps:**
1. Write failing tests for non-authoritative projection fields and admin action permission metadata.
2. Extend `authz.ui` admin contribution to declare tab/action permissions and projection endpoint.
3. Add projection preview in Simulator, clearly marked UX-only.
4. Ensure UI hides disabled actions from projection but API errors still render denial reason.
5. Add tests for admin/frontend context split.

**Verification:** `GOWORK=off go test ./...` in authz-ui repo and `npm test && npm run build && npm run lint` in UI → PASS.

**Rollback:** Revert Task 10 commit; admin contribution continues to expose RBAC page only.

### Task 11: Refreshed Demo and Provider Rotation

**Files:**
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/app/app.py`
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/docker-compose.yml`
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/keto/namespaces.ts`
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/test/run.sh`
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/README.md`
- Create: `/Users/jon/workspace/workflow-scenarios/scenarios/90-admin-tailnet-demo/test/playwright-qa.mjs`

**Steps:**
1. Write failing scenario tests for capabilities endpoint, RBAC select/deselect enforcement, ABAC allow/deny, ReBAC tuple add/delete enforcement, SPA projection, and unsupported mode UI.
2. Expand demo personas: platform admin, readonly admin, frontend user, regional manager, project collaborator, auditor.
3. Add provider selector for `casbin`, `keto`, `permit`; local Casbin/Keto run without external secrets; Permit requires env and marks unavailable otherwise.
4. Implement demo APIs for declarations, capabilities, RBAC, ABAC, ReBAC, decision checks, projection, and audit.
5. Wire Keto relation tuples for ReBAC; Casbin in-process for RBAC/ABAC where model supports; Permit env-gated integration path.
6. Add Tailscale sidecar unchanged; refresh host `tailscale serve` after launch.
7. Add README matrix of personas/use cases and credentials.

**Verification:** `docker compose up --build -d && ./test/run.sh` → all scenario checks PASS; `node test/playwright-qa.mjs` → PASS; `docker compose ps` shows app healthy + Keto running.

**Rollback:** Revert Task 11 commit; run `docker compose down && docker compose up --build -d`; previous demo remains.

### Task 12: Integration, Exploratory QA, and Security Review

**Files:**
- Modify: `docs/plans/2026-05-27-authz-modes-admin.md`
- Create: `docs/security/2026-05-27-authz-modes-review.md`
- Modify only files already owned by Tasks 1-11 when fixing validation findings; any new file or new feature scope requires the scope-lock amendment path.

**Steps:**
1. Run full authz tests: `GOWORK=off go test ./... && wfctl plugin validate-contract .`.
2. Run authz-ui tests/build/lint/contracts.
3. Run scenario docker script and Playwright exploratory QA.
4. Run provider matrix:
   - Casbin local: RBAC/ABAC where configured, ReBAC if `g2`; unsupported modes hidden.
   - Keto local: ReBAC + RBAC-as-relations; ABAC hidden.
   - Permit fake SDK: RBAC/ABAC/ReBAC conformance for implemented methods.
   - Permit live: only when `PERMIT_INTEGRATION=1` and creds set; otherwise record skipped.
5. Security review checklist: fail-closed, confused deputy, CSRF, injection, secret logging, stale projection, audit, tenant/context isolation.
6. Fix all Critical/Important findings.
7. Refresh Tailnet serve and report URL/credentials.

**Verification:** Security report lists PASS/FAIL for each checklist item; all local commands exit 0; Playwright QA PASS; demo reachable at Tailnet URL.

**Rollback:** Revert validation fixes if needed; stop Tailnet serve with `tailscale serve --http=18080 off`; stop docker with `docker compose down`.

## Alignment Matrix

| requirement | tasks |
|---|---|
| Fix misleading capabilities | Preflight `f6ec8f3`, Task 1 |
| RBAC/ABAC/ReBAC support | Tasks 3, 4, 5 |
| Provider advertises support | Task 1 |
| Proper UI for each mode | Tasks 6-10 |
| Use lookups instead of text entry | Tasks 7-9, 11 |
| No false functionality | Tasks 1, 3, 4, 6, 11, 12 |
| Workflow YAML enforcement | Task 5, Task 11 |
| Go/module extensibility | Task 2, Task 5 |
| SPA access reflection | Task 10, Task 11 |
| Third-party plugin declarations | Task 2 |
| Personas/use cases/edge cases | Task 11 |
| Adversarial security review | Task 12 |
| Demo refreshed and tested | Task 11, Task 12 |

## Adversarial Plan Review

**Phase:** plan
**Status:** PASS after revision

| Class | Result | Note |
|---|---|---|
| Project-guidance conflicts | Clean | Plan keeps changes in plugin-owned contracts and scenario/demo repos; no standalone CLI/tool. |
| Assumptions under attack | Clean | Provider-specific uncertainty handled via unsupported descriptors, env-gated Permit, and local Casbin/Keto proof. |
| Repo-precedent conflicts | Clean | Follows existing strict proto, typed step, admin contribution, and scenario test patterns. |
| YAGNI | Clean | Permify and full Casdoor replacement explicitly out of scope. |
| Missing failure modes | Clean | Unsupported provider modes, provider down, stale projection, attr schema drift, tuple delete/deselect are tested. |
| Security/privacy | Clean | Task 12 requires fail-closed, confused deputy, CSRF, injection, secret redaction, projection, audit, and tenant/context checks. |
| Infrastructure impact | Clean | Local Docker/Tailnet only; Permit live path env-gated. |
| Multi-component validation | Clean | Provider packages, UI package, Docker scenario, provider matrix, Playwright QA all required. |
| Rollback | Clean | Each runtime-affecting task includes rollback. |
| Verification-class mismatch | Clean | API/contract/UI/runtime/security tasks have class-appropriate verification. |
| Hidden serial dependencies | Clean | PR grouping serializes provider contracts before UI and demo. |
| Manifest drift | Clean | 4 PRs, 12 tasks, each task listed once. |
| Issue fixed | Fixed | Task 12 originally allowed `Modify as needed`; now restricted to files owned by Tasks 1-11 unless amendment path is used. |
