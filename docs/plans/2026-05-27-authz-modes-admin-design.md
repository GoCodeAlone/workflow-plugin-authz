# Authz Modes Admin Design

## Goal

Build truthful, provider-native authorization management across RBAC, ABAC, and ReBAC:
Workflow YAML can declare/enforce authz, Go modules can expose authz-aware features, the admin UI can manage each supported mode, and SPAs can reflect access without becoming the enforcement boundary.

## Global Design Guidance

Source: `/Users/jon/workspace/docs/design-guidance.md`

| guidance | design response |
|---|---|
| Workflow platform substrate; dogfood plugins/YAML/wfctl | Ship strict plugin contracts, typed steps, scenario YAML/demo proof; no standalone authz tool. |
| Strict-contract invariant | New provider capability, ABAC, ReBAC, and UI runtime contracts use plugin-owned proto messages; free-form attributes cross as typed key/value fields or JSON bytes only where the provider model is intentionally dynamic. |
| Plugin-owned contracts first-class | `workflow-plugin-authz` owns authz provider contracts; `workflow-plugin-authz-ui` consumes them and exposes admin contribution metadata. |
| No mock-first development | Unit tests cover adapters; docker demo exercises real app + admin + Keto; Permit live tests remain opt-in because cloud credentials are external. |
| Secrets never logged | Permit API/PDP keys remain server-only; UI receives capability metadata, catalog entries, and non-sensitive policy shapes only. |
| Multi-component validation | Verify provider package, UI package, docker scenario, Playwright exploratory QA, and workflow YAML checks. |

## External UI / Engine Evaluation

| option | fit | decision |
|---|---|---|
| Casdoor / Casbin admin portal | Casbin docs describe Casdoor and third-party admin portals for model/policy management ([Casbin admin portal](https://casbin.org/docs/admin-portal)); strong for Casbin-only identity/admin, not embeddable provider-neutral Workflow UI. | Do not switch wholesale; borrow model/policy editor patterns for Casbin advanced mode. |
| Casbin library/editor | Casbin supports multiple models via PERM config and management APIs ([Casbin](https://casbin.org/)); useful for model-aware capability detection. | Keep provider adapter; expose safe policy/model views only for Casbin. |
| Ory Keto | Open-source Zanzibar/ReBAC server, headless/API-first ([Ory Keto GitHub](https://github.com/ory/keto)). | Keep as ReBAC provider; UI manages schema metadata + tuples, not a separate Keto UI. |
| Permit.io | SDK-backed SaaS provider already added; supports RBAC/ReBAC/ABAC product surface but live verification needs credentials. | Provider implementation must advertise only implemented surfaces; live tests env-gated. |
| Permify | Open-source authz service for RBAC/ReBAC/ABAC DSL ([Permify GitHub](https://github.com/permify/permify), [modeling docs](https://docs.permify.co/getting-started/modeling)). | Candidate future provider, not current replacement. Adding it now expands provider scope beyond user ask. |

Conclusion: no open-source UI cleanly matches Workflow's embedded, provider-neutral, strict-contract admin need. Continue our own UI, but make it capability-driven, lookup-backed, and mode-native.

## Architecture

### Provider Contracts

`workflow-plugin-authz` exposes one capability discovery contract and three model-native contracts.

| contract | purpose | examples |
|---|---|---|
| `ProviderCapabilities` | Provider says what is supported and configured now. | `rbac/manage_roles/check`, `abac/manage_policies/check`, `rebac/manage_relations/check`, `explain`, `audit`, `schema_required`. |
| `ScopeRoleProvider` | RBAC + scope role management. | Role grants, subject role assignments, direct scopes, context-aware scope check. |
| `AttributePolicyProvider` | ABAC policy/schema/check management. | Attribute definitions, allowed values/lookups, policy rules, decision checks with subject/resource/environment attrs. |
| `RelationshipProvider` | ReBAC relation/schema/check management. | Relation types, tuples, graph lookup, relation check, tuple delete/list. |
| `AuthorizationDecisionProvider` | Unified check surface for YAML/Go/UI. | `subject`, `resource`, `action`, optional scope, attrs, relation context → allow/deny/explain. |

Capability discovery is instance-aware. Casbin derives modes from the loaded model; Keto advertises ReBAC + RBAC-as-relations; Permit advertises surfaces implemented by the SDK adapter and configured project.

### Admin UI

`workflow-plugin-authz-ui` asks `/api/authz/capabilities` first and renders tabs only for supported modes.

| tab | source-of-truth inputs | UX rules |
|---|---|---|
| Overview | provider capabilities + health | show configured provider, enabled modes, unsupported modes, last audit events. |
| RBAC | scope catalog, roles, users, groups | no free-text scopes; roles/scopes/users/resources selected from lookups; direct scope assignment explicit and auditable. |
| ABAC | attribute catalog, resource/action catalog, policy templates | attributes selected from declared dictionaries; operators from provider capabilities; free-text only for declared string attrs where `allow_custom_values=true`. |
| ReBAC | relation schema, subjects/resources, relation tuples | graph-like tuple table with subject/object lookup, relation dropdown, resource type filters, add/remove tuple actions. |
| Simulator | unified decision API | persona picker + resource/action picker + attrs/relations preview; explain output shows provider path and matched rule/tuple/scope. |
| Audit | append-only events | filters by actor/mode/resource/action; never logs secrets or raw tokens. |

Unsupported modes are hidden by default, with a compact disabled state in Overview to avoid implying false functionality.

### Workflow YAML

YAML gets mode-native typed steps plus a unified decision step:

| step | use |
|---|---|
| `step.authz_capabilities` | branch pipeline or fail startup if required mode missing. |
| `step.authz_check` | unified check for handlers/workflows; returns allow/deny/explain. |
| `step.authz_rbac_assign`, `step.authz_rbac_remove`, `step.authz_rbac_check` | role/scope administration and enforcement. |
| `step.authz_abac_policy_upsert`, `step.authz_abac_policy_remove`, `step.authz_abac_check` | attribute policy lifecycle. |
| `step.authz_rebac_tuple_upsert`, `step.authz_rebac_tuple_remove`, `step.authz_rebac_check` | relationship lifecycle. |

YAML can require capabilities declaratively:

```yaml
modules:
  - name: authz
    type: authz.keto
    config: { read_url: http://keto:4466, write_url: http://keto:4467 }
    requires:
      authz:
        modes: [rebac]
        operations: [check, manage_relations]
```

### Go / Module Code

Third-party plugins declare authz facts without choosing the application engine:

| declaration | owned by plugin | consumed by app/admin |
|---|---|---|
| Scope declarations | feature/action visibility and coarse checks. | RBAC providers, SPA permission projection. |
| Attribute schema | subject/resource/environment attrs with types, lookups, validation. | ABAC UI and decision checks. |
| Resource/action catalog | known resource types, actions, owner plugin/module. | all modes, simulator, policy forms. |
| Relation schema | resource types and relation names. | ReBAC UI and provider schema. |
| UI contribution metadata | required permissions for view/action. | admin shell and SPA rendering. |

Declarations are engine-agnostic. The app chooses provider; unsupported provider/mode combinations fail with explicit startup/API errors rather than silently degrading.

### SPA Access Projection

SPAs receive a non-authoritative permission projection:

```json
{
  "subject": "alice",
  "context": "frontend",
  "capabilities": ["rbac", "rebac"],
  "scopes": ["frontend:orders:read"],
  "ui": {
    "views": [{"id": "orders", "visible": true}],
    "actions": [{"id": "orders.resolve", "enabled": false, "reason": "missing scope"}]
  }
}
```

Projection is for UX only. Mutating backend APIs still call the unified decision provider.

## Personas / Use Cases

| persona | use case | mode |
|---|---|---|
| Platform admin | assign admin dashboard permissions to support staff. | RBAC |
| Product manager | allow regional managers to edit only region-owned campaigns. | ABAC |
| Tenant admin | share one project/doc with a collaborator. | ReBAC |
| Developer/plugin author | declare resources/actions/attrs/relations once in plugin proto. | all |
| Frontend engineer | hide disabled UI actions without hardcoding roles. | projection |
| Security auditor | inspect who changed a policy or tuple. | audit |

## Edge Cases

| edge | required behavior |
|---|---|
| Provider lacks mode requested by app | startup/API validation fails closed with capability error. |
| Provider temporarily down | decision checks fail closed; UI shows degraded provider health. |
| Attribute schema changes while policies exist | migration report lists affected policies; destructive removal blocked unless policies removed first. |
| Relation tuple references missing object | provider may store tuple, but UI flags unresolved lookup; decision still provider-authoritative. |
| User loses admin scope while viewing admin | next API request denies; UI refresh hides actions. |
| SPA projection stale | backend enforcement wins; projection TTL short and revalidated on session refresh. |
| Permit credentials absent | live Permit tests skip; demo can run Casbin/Keto locally; UI marks Permit unavailable. |
| Text-entry temptation | form fields use lookups for scopes/resources/actions/users/relations/operators; free-text only for declared dynamic attributes. |

## Security Review

| area | control |
|---|---|
| Authn/authz boundary | Admin UI requires auth plugin session plus backend authz checks; SPA projection is advisory. |
| Least privilege | Each admin tab/action has required scope/mode operation; missing grants hide UI and deny API. |
| Confused deputy | All checks carry `context`, `resource`, `action`, provider, and actor; admin/frontend contexts cannot be inferred from path alone. |
| CSRF | Mutating admin APIs require session + CSRF token or same-site POST token in scenario/admin implementation. |
| Injection | Attribute values and tuple components validate against declared schema; provider DSL/model text editing limited to advanced mode and audited. |
| Secrets | Permit keys/PDP URLs stay server-side; logs redact credentials. |
| Audit | policy/role/tuple mutations append actor, mode, resource, action, before/after IDs. |

## Infrastructure Impact

| item | impact |
|---|---|
| Local demo | Docker Compose runs app + Keto; optional Permit requires env secrets; optional Casbin runs in-process. |
| Network | Tailnet serve remains local; no production deploy. |
| Storage | Demo in-memory; plugin contracts allow provider persistence but no migration in this phase unless provider needs it. |
| Secrets | Permit live integration env-gated: `PERMIT_API_KEY`, `PERMIT_PROJECT`, `PERMIT_ENVIRONMENT`, `PERMIT_INTEGRATION=1`. |
| Cost | No live SaaS calls unless env opt-in. |

## Multi-Component Validation

| proof | expected |
|---|---|
| `workflow-plugin-authz` unit + contract tests | provider capability, RBAC, ABAC, ReBAC contracts pass. |
| Provider conformance matrix | Casbin/Keto local pass; Permit fake SDK pass; Permit live env-gated pass when creds set. |
| `workflow-plugin-authz-ui` unit/build/lint | capability-driven tabs, lookup-backed forms, no false tabs. |
| Scenario script | app/admin/RBAC/ABAC/ReBAC endpoints and enforcement pass. |
| Docker runtime | app + Keto healthy; provider rotation works for local providers. |
| Playwright exploratory QA | login, tabs, lookup forms, select/deselect, enforcement, denied UI, mobile layout. |

## Rollback

| change | rollback |
|---|---|
| Authz contracts/providers | revert provider contract commits; run `GOWORK=off go test ./...`; old scope-role path remains. |
| Authz UI | revert UI commits; `npm test && npm run build && npm run lint`; old RBAC-only UI remains. |
| Scenario | revert scenario commits; `docker compose down && docker compose up --build -d`; previous RBAC/Keto scope demo remains. |
| Demo Tailnet serve | `tailscale serve --http=18080 off`; docker sidecar idle if `TS_AUTHKEY` absent. |

## Assumptions

| id | assumption | challenge | fallback |
|---|---|---|---|
| A1 | Provider-neutral admin can be mode-native without abstracting away semantics. | one form might not fit every provider. | Capability-specific tabs and provider-specific advanced pane. |
| A2 | Third-party plugins can declare resources/scopes/attrs/relations without knowing provider choice. | some provider schemas need provider-specific model syntax. | Shared declarations generate baseline provider schema; provider-specific extension block optional. |
| A3 | Casbin ABAC can be detected from model text enough for truthful capabilities. | model analysis can miss custom funcs. | Allow explicit capability override only if model tests pass; show `detected` vs `declared`. |
| A4 | Permit live environment may not be available locally/CI. | no real Permit verification by default. | Fake SDK conformance + env-gated live suite + UI unavailable state. |
| A5 | UI should avoid free text wherever possible. | users need custom string attrs. | Allow custom only for schema-declared dynamic attributes. |

## Self-Challenge

| doubt | response |
|---|---|
| Could this be just Casdoor/Casbin portal? | No: it is Casbin-specific and not Workflow provider-neutral/admin-contribution native. |
| Is unified decision API too much? | Needed to make YAML, Go modules, and SPA projection use one enforcement surface while preserving model-native management APIs. |
| Is ABAC UI overreach? | User explicitly asked ABAC and user-friendly lookup-backed forms; plan scopes ABAC to declared schemas/policies, not arbitrary DSL authoring first. |

