# Scope Provider Engines Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Provide declared-scope role management across Casbin, Permit.io SDK, and Ory Keto SDK, update authz-ui to select known scopes, and run the demo on a new provider.

**Architecture:** `workflow-plugin-authz` owns a normalized scope-role provider contract and adapters. `workflow-plugin-authz-ui` consumes the normalized scope catalog/role APIs with a catalog-backed picker. `workflow-scenarios` demonstrates the same role/scope semantics with Keto as the default locally runnable provider.

**Tech Stack:** Go protobuf contracts, Workflow external SDK, Casbin, `github.com/permitio/permit-golang@v1.2.8`, `github.com/ory/keto-client-go/v25@v25.4.0`, React/Vite/TypeScript, Docker Compose, Playwright/curl.

**Base branch:** `workflow-plugin-authz` `main`; `workflow-plugin-authz-ui` `feat/admin-authz-ui-integration`; `workflow-scenarios` `pr-27`.

---

## Scope Manifest

**PR Count:** 3
**Tasks:** 5
**Estimated Lines of Change:** ~1800

**Out of scope:**
- Ory Hydra integration.
- Preserving the unused old Permit REST step/module contract.
- Building a full policy designer, tenant admin UI, or persistent role database beyond provider-backed storage.
- Running real Permit SaaS integration without credentials in the environment.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Scope-backed authz provider engines | Task 1, Task 2, Task 3 | workflow-plugin-authz: feat/scope-provider-engines |
| 2 | Declared-scope authz UI picker | Task 4 | workflow-plugin-authz-ui: feat/scope-picker |
| 3 | Keto-backed admin tailnet demo | Task 5 | workflow-scenarios: feat/keto-admin-demo |

**Status:** Locked 2026-05-27T03:09:41Z

### Task 1: Normalized Scope-Role Provider Contract

**Files:**
- Modify: `workflow-plugin-authz/internal/contracts/authz.proto`
- Modify: `workflow-plugin-authz/internal/contracts/authz.pb.go`
- Modify: `workflow-plugin-authz/internal/plugin.go`
- Modify: `workflow-plugin-authz/internal/typed.go`
- Modify: `workflow-plugin-authz/plugin.contracts.json`
- Create: `workflow-plugin-authz/internal/scope_role_provider.go`
- Create: `workflow-plugin-authz/internal/scope_role_provider_test.go`
- Modify: `workflow-plugin-authz/internal/module_casbin.go`
- Test: `workflow-plugin-authz/internal/scope_catalog_test.go`

**Step 1: Write failing tests**

Add tests for:
- unknown scope grants rejected against catalog;
- role assignment stores `subject`, `role`, `context`, `scopes`;
- `CheckScope` allows assigned frontend scope and denies admin scope for same user;
- Casbin adapter satisfies shared conformance.

Run: `GOWORK=off go test ./internal -run 'TestScopeRoleProvider|TestCasbinScopeRoleConformance'`
Expected: FAIL because provider contract/types do not exist.

**Step 2: Implement contract**

Add proto messages: `ScopeRoleProviderConfig`, `RoleScopeGrant`, `SubjectRoleAssignment`, `ScopeCheckInput`, `ScopeCheckOutput`, `ListRoleAssignmentsInput/Output`, and service contracts for assign/list/remove/check. Add Go interface + registry. Adapt Casbin with in-memory normalized scope policies.

Regenerate: `protoc --go_out=. --go_opt=paths=source_relative internal/contracts/authz.proto`

**Step 3: Verify**

Run: `GOWORK=off go test ./internal -run 'TestScopeRoleProvider|TestCasbinScopeRoleConformance|TestScopeCatalog'`
Expected: PASS.

Rollback: revert Task 1 files and regenerate proto from prior `authz.proto`.

### Task 2: Permit.io SDK Provider

**Files:**
- Modify: `workflow-plugin-authz/go.mod`
- Modify: `workflow-plugin-authz/go.sum`
- Replace/remove: `workflow-plugin-authz/internal/permit_client.go`
- Modify: `workflow-plugin-authz/internal/module_permit.go`
- Modify: `workflow-plugin-authz/internal/permit_registry.go`
- Modify/remove as needed: `workflow-plugin-authz/internal/step_permit*.go`
- Create: `workflow-plugin-authz/internal/provider_permit.go`
- Create: `workflow-plugin-authz/internal/provider_permit_test.go`
- Modify: `workflow-plugin-authz/internal/capabilities.go`

**Step 1: Write failing tests**

Add tests proving:
- `permit.provider` constructs via official SDK types, not custom HTTP client;
- adapter maps declared scopes to Permit resources/actions;
- adapter maps role assignments to Permit role/permission operations through an SDK-facing client interface;
- `CheckScope` result follows SDK/PDP allow/deny.

Run: `GOWORK=off go test ./internal -run 'TestPermitSDKProvider'`
Expected: FAIL because SDK adapter is absent.

**Step 2: Add SDK and implementation**

Run: `GOWORK=off go get github.com/permitio/permit-golang@v1.2.8`

Implement Permit adapter with official SDK/openapi clients from that module. Remove handwritten request builder as provider implementation. Keep any generic Permit step only if it delegates through SDK/openapi clients; otherwise remove from contract registry because compatibility is out of scope.

**Step 3: Verify**

Run: `GOWORK=off go test ./internal -run 'TestPermitSDKProvider|TestScopeRoleProviderConformance'`
Expected: PASS with mocked SDK boundary.

Run when env exists: `PERMIT_INTEGRATION=1 GOWORK=off go test ./internal -run TestPermitRealIntegration -count=1`
Expected with credentials: PASS; without required env vars: SKIP message naming missing vars.

Rollback: revert Task 2 files; `go mod tidy`; Casbin/Keto providers remain unaffected.

### Task 3: Ory Keto SDK Provider

**Files:**
- Modify: `workflow-plugin-authz/go.mod`
- Modify: `workflow-plugin-authz/go.sum`
- Create: `workflow-plugin-authz/internal/module_keto.go`
- Create: `workflow-plugin-authz/internal/provider_keto.go`
- Create: `workflow-plugin-authz/internal/provider_keto_test.go`
- Create: `workflow-plugin-authz/internal/provider_keto_integration_test.go`
- Modify: `workflow-plugin-authz/internal/plugin.go`
- Modify: `workflow-plugin-authz/internal/contracts/authz.proto`
- Modify: `workflow-plugin-authz/internal/contracts/authz.pb.go`
- Modify: `workflow-plugin-authz/plugin.contracts.json`

**Step 1: Write failing tests**

Add tests for tuple naming:
- subject role tuple: `role:<context>:<role>#member@user:<subject>`;
- role scope tuple: `scope:<context>:<resource>:<action>#granted@role:<context>:<role>`;
- optional direct scope tuple: `scope:<context>:<resource>:<action>#granted@user:<subject>`;
- `CheckScope` calls Keto check and fails closed on errors.

Run: `GOWORK=off go test ./internal -run 'TestKetoProvider'`
Expected: FAIL because Keto module/provider do not exist.

**Step 2: Add SDK and implementation**

Run: `GOWORK=off go get github.com/ory/keto-client-go/v25@v25.4.0`

Implement `authz.keto` module config with read/write URLs and namespace prefix. Use official SDK client for tuple writes and checks. Register provider and strict contract.

**Step 3: Verify**

Run: `GOWORK=off go test ./internal -run 'TestKetoProvider|TestScopeRoleProviderConformance'`
Expected: PASS.

Run local integration if Docker available: `KETO_INTEGRATION=1 GOWORK=off go test ./internal -run TestKetoRealIntegration -count=1`
Expected: PASS when test starts/reaches local Keto, otherwise SKIP with explicit Docker/env reason.

Rollback: revert Task 3 files; remove Keto service/deps; run `go mod tidy`.

### Task 4: Authz UI Declared-Scope Picker

**Files:**
- Modify: `workflow-plugin-authz-ui/ui/src/components/RoleTable.tsx`
- Modify: `workflow-plugin-authz-ui/ui/src/styles/index.css`
- Modify: `workflow-plugin-authz-ui/ui/src/types.ts`
- Modify: `workflow-plugin-authz-ui/ui/src/api.ts`
- Modify: `workflow-plugin-authz-ui/ui/test/source-contract.test.mjs`
- Add if needed: `workflow-plugin-authz-ui/ui/test/scope-picker.test.mjs`

**Step 1: Write failing tests**

Update source/static tests to assert:
- no `"Direct scopes, comma separated"` input exists;
- scope controls are checkboxes/buttons/selectable chips sourced from `scopes`;
- submitted role payload uses `scopes: string[]`;
- unknown free-text scopes cannot be entered.

Run: `cd ui && npm test`
Expected: FAIL because current UI has text entry.

**Step 2: Implement picker**

Replace text input with grouped/searchable selectable scope list filtered by selected context. Render selected scopes as removable chips. Keep API base path configurable.

**Step 3: Verify**

Run: `cd ui && npm test && npm run build && npm run lint`
Expected: PASS.

Rollback: revert Task 4 files and rebuild prior UI.

### Task 5: Keto-Backed Demo and Runtime QA

**Files:**
- Modify: `workflow-scenarios/scenarios/90-admin-tailnet-demo/app/app.py`
- Modify: `workflow-scenarios/scenarios/90-admin-tailnet-demo/docker-compose.yml`
- Modify: `workflow-scenarios/scenarios/90-admin-tailnet-demo/README.md`
- Modify: `workflow-scenarios/scenarios/90-admin-tailnet-demo/test/run.sh`
- Add if needed: `workflow-scenarios/scenarios/90-admin-tailnet-demo/keto/`

**Step 1: Write failing scenario checks**

Add checks for:
- `/api/status` reports `authz.provider == "keto"`;
- admin scope picker renders selectable known scopes, not text scope field;
- assigning a declared admin scope affects access;
- assigning an unknown scope returns 400;
- frontend-only user remains denied from admin.

Run: `./test/run.sh`
Expected: FAIL before demo changes.

**Step 2: Add local Keto demo wiring**

Add Keto service/config to compose. Seed relation tuples for demo roles/scopes at app startup or test setup. App uses provider selector `AUTHZ_PROVIDER=keto` by default and fails closed when provider unavailable. Keep Tailscale sidecar unchanged.

**Step 3: Runtime launch**

Run: `docker compose up --build -d`
Expected: app and Keto healthy.

Run: `./test/run.sh`
Expected: `passed` count includes provider-backed role checks; zero failures.

Run Playwright/curl smoke:
- anonymous `/admin` redirects to login;
- admin login sees Authz page and picker options;
- readonly admin cannot update roles;
- app user cannot access admin;
- `/api/status` reports Keto provider.

Scrape: `docker compose logs --no-color | rg -i 'panic|traceback|exception|permission denied|address already in use|connection refused'`
Expected: no failure-signature hits.

Rollback: `docker compose down -v`; revert Task 5 files; optionally `tailscale serve --http=18080 off`.

## Adversarial Plan Review

Status: PASS after inline adversarial review.

Required framing used: find at least three things wrong with this plan; bias
toward hidden dependencies, verification mismatch, and scope drift.

### Findings

| sev | class | issue | resolution |
|---|---|---|---|
| Important | PR grouping | Initial manifest collapsed three repos into one PR row. | Fixed manifest: 3 PR rows for authz, authz-ui, scenario. |
| Minor | Verification mismatch | Permit SaaS cannot be forced in local env. | Task 2 explicitly distinguishes mandatory conformance from env-gated real integration and forbids pass claim on skip. |
| Minor | Hidden dependency | Scenario depends on Keto provider semantics from Task 3. | PR grouping keeps scenario after authz core; Task 5 provider selector defaults to Keto after provider exists. |
| Minor | SDK bypass risk | Demo could become a provider implementation if it directly substitutes for Go SDK adapter proof. | Task 5 is runtime demo only; Tasks 2/3 own SDK compile and conformance proof. |

### Bug-Class Scan

| class | result | note |
|---|---|---|
| Project-guidance conflicts | Clean | Tasks follow plugin ownership and multi-component validation guidance. |
| Assumptions under attack | Clean | Fragile Permit/Keto assumptions have explicit tests/skips/fallbacks. |
| Repo-precedent conflicts | Finding | Cross-repo PR collapse fixed by 3-row manifest. |
| YAGNI | Clean | No tenant/policy designer/migration UI added. |
| Missing failure modes | Clean | Provider unavailable → fail closed; Keto readiness/log scrape covered. |
| Security/privacy | Clean | Unknown scope reject and least-privilege route checks covered. |
| Infrastructure impact | Clean | Docker Keto local only; rollback listed. |
| Multi-component validation | Clean | Go SDK tests, UI build/lint, Docker app+keto, curl/Playwright paths included. |
| Rollback story | Clean | Every runtime/dependency task has rollback note. |
| Simpler alternative | Clean | Casbin-only rejected by approved design. |
| User-intent drift | Clean | Uses Keto, ignores Hydra, permits breaking old Permit provider contract. |
| Over/under-decomposition | Clean | 5 tasks map to independent components and review boundaries. |
| Verification-class mismatch | Finding | Permit real SaaS integration env-gated; plan requires explicit SKIP vs PASS. |
| Hidden serial dependencies | Finding | Scenario depends on Task 3; ordering is explicit. |
| Missing rollback wiring | Clean | Rollback steps included per task. |
| Missing integration proof | Clean | Keto local integration and runtime scenario provide real boundary proof. |
| Infrastructure verification mismatch | Clean | Compose launch, health, log scrape covered for local infra. |

Verdict: PASS. Important finding fixed in manifest; remaining findings are implementation guardrails.

## Alignment Report

**Status:** PASS

**Coverage:**

| Design Requirement | Plan Task(s) | Status |
|---|---|---|
| Declared-scope role model and unknown-scope rejection | Task 1 | Covered |
| Normalized provider interface and strict proto contracts | Task 1 | Covered |
| Casbin adapter conformance | Task 1 | Covered |
| Permit.io official Go SDK provider, old REST compatibility not required | Task 2 | Covered |
| Ory Keto official Go SDK provider | Task 3 | Covered |
| Provider rotation/conformance tests | Task 1, Task 2, Task 3 | Covered |
| Authz UI scope picker with no free-text scope entry | Task 4 | Covered |
| Demo uses a newly added engine | Task 5 | Covered |
| Security: fail closed, least privilege, no secrets in UI | Task 1, Task 2, Task 3, Task 5 | Covered |
| Infrastructure: local Keto compose, Permit env-gated | Task 2, Task 3, Task 5 | Covered |
| Multi-component validation | Task 2, Task 3, Task 4, Task 5 | Covered |
| Rollback | Task 1, Task 2, Task 3, Task 4, Task 5 | Covered |

**Scope Check:**

| Plan Task | Design Requirement | Status |
|---|---|---|
| Task 1 | Canonical role/scope model, Casbin conformance, strict contracts | Justified |
| Task 2 | Permit SDK provider | Justified |
| Task 3 | Keto SDK provider | Justified |
| Task 4 | Declared-scope picker | Justified |
| Task 5 | Keto-backed demo and runtime QA | Justified |

**Drift Items:** none. `plan-scope-check.sh --plan /Users/jon/workspace/workflow-plugin-authz/docs/plans/2026-05-27-scope-provider-engines.md` → PASS.
