# Scope Provider Engines Design

## User Ask

Implement scope picker backed by declared scopes; replace unused Permit REST
contract with official Permit.io Go SDK; add Ory Keto as third authz provider
using official SDK; verify role→scope assignment and enforcement rotate across
providers; update demo to use one newly added engine. Ignore prior Hydra
mention.

## Global Design Guidance

Source: `/Users/jon/workspace/AGENTS.md`; `workflow-plugin-authz-ui/docs/plans/2026-05-27-admin-authz-ui-design.md`.

| guidance | design response |
|---|---|
| Dogfood Workflow/plugin ecosystem | Authz provider modules expose strict proto contracts and shared methods; authz-ui consumes normalized API. |
| Repo ownership boundaries | `workflow-plugin-authz` owns provider adapters/enforcement; `workflow-plugin-authz-ui` owns selection UX; `workflow-scenarios` owns demo wiring. |
| Security/quality on platform surfaces | Default-deny checks, declared-scope validation, no arbitrary scope grants, provider conformance tests. |
| Use real integrations | Permit via `github.com/permitio/permit-golang`; Keto via `github.com/ory/keto-client-go/v25`; no handwritten provider REST clients. |
| Multi-component validation | Unit conformance + SDK integration gates + running demo + Playwright/curl authz checks. |

## Design

### Canonical Model

| object | shape | notes |
|---|---|---|
| scope | `context:resource:action` + metadata | Declared by modules through scope catalog; free-text grants rejected by admin UI/API. |
| role | `name`, `context`, `scopes[]` | One role namespace with context dimension; roles can be shared by name only when context matches. |
| assignment | `subject`, `role`, `context`, optional direct `scopes[]` | Direct scopes still validate against catalog; role scopes and direct scopes merge at check time. |
| check | `subject`, `context`, `scope` or `resource/action` | Normalized before provider call; result includes provider, matched grants, denied reason. |

### Provider Interface

`workflow-plugin-authz` adds an internal conformance interface:

```go
type ScopeRoleProvider interface {
    Name() string
    DeclareScopes(context.Context, []*contracts.ScopeDeclaration) error
    UpsertRole(context.Context, RoleScopeGrant) error
    AssignRole(context.Context, SubjectRoleAssignment) error
    ListAssignments(context.Context, AssignmentFilter) ([]SubjectRoleAssignment, error)
    RemoveAssignment(context.Context, SubjectRoleAssignment) error
    CheckScope(context.Context, ScopeCheck) (ScopeCheckResult, error)
}
```

Strict proto service methods wrap this model so Workflow modules, admin, and
scenarios do not depend on provider-specific SDK types.

### Providers

| provider | implementation | persistence/eval |
|---|---|---|
| Casbin | existing `authz.casbin` adapted to scope-role interface | Local memory/file/gorm Casbin policies; good local default. |
| Permit.io | replace unused custom REST client with official SDK module `github.com/permitio/permit-golang@v1.2.8` | SDK management APIs create roles/resources/actions; SDK/PDP checks enforce. Integration tests require Permit env vars. |
| Ory Keto | new `authz.keto` module using `github.com/ory/keto-client-go/v25@v25.4.0` | Roles/scopes represented as Keto relationship tuples; check API evaluates subject relation to context/resource/action object. Local Docker Keto used in scenario/tests. |

Permit provider contract compatibility is not preserved because user confirmed it is unused.

### Authz UI Scope Picker

`workflow-plugin-authz-ui` replaces comma-separated scope entry with a declared
scope picker:

- load `/scopes` from configurable API base path;
- group by context/category/resource; search by name/resource/description;
- filter to selected role context by default;
- selected scopes render as removable chips;
- submit only catalog scope names;
- no free-text fallback.

### Demo

`workflow-scenarios/scenarios/90-admin-tailnet-demo` moves from in-memory
scope checks to a provider-backed check path. Default demo engine: **Ory Keto**
because it can run locally in Docker without SaaS credentials and proves a new
provider in the running app. Provider selector remains configurable so tests can
run `casbin`, `keto`, and Permit when credentials are present.

## Security Review

| topic | design |
|---|---|
| Authn | Demo/admin routes still require login/session before authz checks. |
| Authz | UI is advisory; API rejects undeclared scopes and provider `CheckScope` gates routes/actions. |
| Least privilege | Admin role management needs `admin:authz.roles:update`; scope read needs `admin:authz.scopes:read`. |
| Provider trust | SDK clients are isolated behind provider adapters; no provider secrets exposed to UI/runtime config. |
| Abuse cases | Unknown scope grant, wrong context, absent provider, failed network check → deny. |
| Audit | Role assignment/check errors include provider + safe reason, never API keys or tokens. |

## Infrastructure Impact

| item | impact |
|---|---|
| Go deps | Add Permit SDK and Keto SDK to `workflow-plugin-authz`. |
| Docker demo | Add Keto service and init wiring; Permit remains env-gated because SaaS credentials are required. |
| Network | Demo exposes same app port/Tailscale serve; Keto internal Docker network only. |
| Secrets | Permit tests use env vars only; no committed keys. |
| Prod approval | None; local/demo only. |

## Multi-Component Validation

| proof | command/evidence |
|---|---|
| Provider conformance | `GOWORK=off go test ./internal -run TestScopeRoleProviderConformance` across casbin/keto/permit fake SDK boundary. |
| SDK compile | `GOWORK=off go test ./...` proves official SDK usage compiles. |
| Keto integration | Docker Keto + Go integration test or scenario check exercises real write/check boundary. |
| Permit integration | Env-gated real Permit test runs when `PERMIT_API_KEY`/project/env present; otherwise skipped with explicit message. |
| UI | `cd ui && npm test && npm run build && npm run lint`; Playwright confirms picker has selectable scopes and no text scope entry. |
| Scenario | Docker compose app+keto; curl/Playwright verify login, role assignment, allowed/denied frontend/admin actions. |

## Rollback

| change | rollback |
|---|---|
| Provider adapters/proto | Revert authz provider commits; run `GOWORK=off go test ./...`; Casbin legacy module remains rollback baseline. |
| UI picker | Revert authz-ui commit; rebuild UI; older API payload remains compatible if server accepts `scopes[]`. |
| Demo Keto service | `docker compose down -v`; revert scenario files; relaunch prior app; `tailscale serve --http=18080 off` if needed. |
| Dependency pins | Revert `go.mod`/`go.sum`; rerun Go tests. |

## Assumptions

| id | assumption | challenge | fallback |
|---|---|---|---|
| A1 | Scope catalog is the source of truth for grantable scopes. | Legacy payloads may include unknown scopes. | Reject new unknown grants; render existing unknown grants as provider drift requiring cleanup. |
| A2 | Permit SDK exposes required role/resource/check surfaces. | SDK lacks some management method ergonomics. | Use SDK-generated OpenAPI clients from the same module, not custom HTTP. |
| A3 | Keto relationship tuples can model role→scope and subject→role checks cleanly. | Tuple schema may need namespace choices. | Use minimal documented namespace layout and conformance tests; no app-specific assumptions. |
| A4 | Keto can run locally in Docker scenario. | Startup/migration order may be brittle. | Add health/readiness wait and fail closed; keep Casbin selector for local fallback tests. |
| A5 | Provider rotation should verify same semantics, not same storage shape. | Engines differ internally. | Conformance asserts external allow/deny/list behavior only. |

## Self-Challenge

| doubt | response |
|---|---|
| Could this just be UI picker + Casbin? | No; user explicitly requested Permit SDK, Keto SDK, provider rotation, and demo using a new engine. |
| Is a normalized provider abstraction overbuilt? | Without it, UI/demo would branch per engine and role/scope semantics would drift. |
| What fails first? | External provider unavailability. Design requires default-deny, skipped/gated SaaS tests, and local Keto readiness checks. |
| Does this solve unasked features? | No policy designer/tenant UI/migrations; only scope grants, role assignments, checks, and provider adapters. |
| Repo pattern conflict? | Fits existing module/provider plugin shape; replaces unused Permit contract only with user approval. |

## Approved Direction

User approved on 2026-05-27 and clarified: use Ory Keto, ignore Hydra mention,
do not preserve existing Permit provider contract.

## Adversarial Design Review

Status: PASS after inline adversarial review.

Required framing used: find at least three things wrong with this design;
bias toward misconceptions, unstated assumptions, missing failure modes, and
simpler alternatives.

### Findings

| sev | class | issue | resolution |
|---|---|---|---|
| Minor | Multi-component validation | Permit real enforcement cannot be proven locally without SaaS credentials. | Keep unit conformance mandatory; make real Permit integration env-gated and report SKIP explicitly when credentials absent. Do not claim real Permit integration passed unless env-gated test ran. |
| Minor | Repo precedent | Scenario is currently Python/in-memory; a direct Python Keto call could bypass Go SDK provider integration. | Plan must keep SDK proof in `workflow-plugin-authz` and make scenario clearly a demo consumer of provider semantics, not the provider implementation. |
| Minor | Failure mode | Keto tuple schema is underspecified and could drift from role/scope model. | Plan must define tuple/object naming in a dedicated task and verify with a real Keto check. |

### Bug-Class Scan

| class | result | note |
|---|---|---|
| Project-guidance conflicts | Clean | Follows Workflow/plugin ownership, strict proto, security, and multi-component proof guidance. |
| Assumptions under attack | Finding | A2/A3/A4 are fragile; design lists fallback and plan must verify exact SDK/Keto behavior. |
| Repo-precedent conflicts | Finding | Python demo precedent can bypass SDK; resolved by separating demo consumer from Go SDK provider proof. |
| YAGNI | Clean | No tenant UI, policy designer, migration layer, or generalized identity system. |
| Missing failure modes | Finding | External provider outage and Keto readiness addressed as default-deny/readiness checks. |
| Security/privacy | Clean | Unknown grants rejected, provider errors fail closed, secrets stay server/env only. |
| Infrastructure impact | Clean | Local Docker Keto only; Permit env-gated; no production resources. |
| Multi-component validation | Finding | Permit real boundary depends on credentials; design requires explicit skip vs pass distinction. |
| Rollback story | Clean | Revert deps/provider/UI/demo and stop Docker/Tailscale paths covered. |
| Simpler alternative | Clean | Scope picker + Casbin-only rejected because user requested Permit/Keto/provider rotation. |
| User-intent drift | Clean | Hydra removed; Keto is third provider per user correction. |

### Options Considered

1. UI picker + Casbin only: simplest, but fails explicit provider requirements.
2. Permit/Keto as step-only integrations: smaller API surface, but admin cannot
   administer roles/scopes uniformly across engines.
3. Full normalized provider interface: more code, but required to rotate engines
   without UI/demo branching and to conformance-test semantics.

Verdict: PASS. Findings are plan-level guardrails, not design blockers.
