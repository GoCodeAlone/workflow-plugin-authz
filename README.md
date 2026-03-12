# workflow-plugin-authz

RBAC authorization plugin for the [workflow engine](https://github.com/GoCodeAlone/workflow) using [Casbin](https://casbin.org/).

## Capabilities

| Type | Name |
|---|---|
| Module | `authz.casbin` |
| Step | `step.authz_check_casbin` |
| Step | `step.authz_add_policy` |
| Step | `step.authz_remove_policy` |
| Step | `step.authz_role_assign` |

## authz.casbin module

Loads a Casbin PERM model and policy from inline YAML config. The enforcer is thread-safe and shared with all `step.authz_check_casbin` steps that reference the module by name.

```yaml
modules:
  - name: authz
    type: authz.casbin
    config:
      model: |
        [request_definition]
        r = sub, obj, act
        [policy_definition]
        p = sub, obj, act
        [role_definition]
        g = _, _
        [policy_effect]
        e = some(where (p.eft == allow))
        [matchers]
        m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
      policies:
        - ["admin", "/*", "*"]
        - ["editor", "/api/*", "GET"]
        - ["editor", "/api/*", "POST"]
        - ["viewer", "/api/*", "GET"]
      roleAssignments:
        - ["alice", "admin"]
        - ["bob", "editor"]
        - ["carol", "viewer"]
```

## step.authz_check_casbin pipeline step

Checks whether the authenticated user (injected by `step.auth_required`) has permission to perform the configured action on the configured object. Returns HTTP 403 and stops the pipeline on denial.

```yaml
steps:
  - type: step.auth_required   # sets auth_user_id in output
    config: {}

  - type: step.authz_check_casbin
    config:
      module: authz             # authz.casbin module name (default: "authz")
      subject_key: auth_user_id # step output key for the subject (default: "auth_user_id")
      object: "/api/v1/tenants" # static path, or Go template: "{{.request_path}}"
      action: "POST"            # static method, or Go template: "{{.request_method}}"
```

On success the step outputs:

```json
{
  "authz_subject": "alice",
  "authz_object": "/api/v1/tenants",
  "authz_action": "POST",
  "authz_allowed": true
}
```

On denial (HTTP 403):

```json
{
  "response_status": 403,
  "response_body": "{\"error\":\"forbidden: bob is not permitted to POST /api/v1/tenants\"}",
  "response_headers": {"Content-Type": "application/json"},
  "authz_allowed": false
}
```

## step.authz_add_policy pipeline step

Adds a policy rule to the Casbin enforcer at runtime. Each element of `rule` may be a static string or a Go template rendered against the merged pipeline context (trigger data, prior step outputs, and current context).

```yaml
steps:
  - type: step.authz_add_policy
    config:
      module: authz                        # authz.casbin module name (default: "authz")
      rule: ["editor", "/api/posts", "POST"] # policy rule; each element may be a Go template
```

Template-based rule (values resolved from the pipeline context at runtime):

```yaml
steps:
  - type: step.authz_add_policy
    config:
      module: authz
      rule: ["{{.role}}", "{{.resource}}", "{{.method}}"]
```

On success the step outputs:

```json
{
  "authz_policy_added": true,
  "authz_rule": ["editor", "/api/posts", "POST"]
}
```

`authz_policy_added` is `false` when the rule already existed in the enforcer.

## step.authz_remove_policy pipeline step

Removes a policy rule from the Casbin enforcer at runtime. Mirrors `step.authz_add_policy` in configuration; each element of `rule` may be a static string or a Go template.

```yaml
steps:
  - type: step.authz_remove_policy
    config:
      module: authz                        # authz.casbin module name (default: "authz")
      rule: ["editor", "/api/posts", "POST"] # policy rule to remove; elements may be Go templates
```

Template-based rule:

```yaml
steps:
  - type: step.authz_remove_policy
    config:
      module: authz
      rule: ["{{.role}}", "{{.resource}}", "{{.method}}"]
```

On success the step outputs:

```json
{
  "authz_policy_removed": true,
  "authz_rule": ["editor", "/api/posts", "POST"]
}
```

`authz_policy_removed` is `false` when the rule did not exist in the enforcer.

## step.authz_role_assign pipeline step

Adds or removes role mappings (grouping policies) in the Casbin enforcer at runtime. Useful for provisioning authorization when new users or tenants are onboarded.

| Config field | Type | Default | Description |
|---|---|---|---|
| `module` | string | `"authz"` | Name of the `authz.casbin` module |
| `action` | string | `"add"` | `"add"` to assign a role, `"remove"` to revoke it |
| `assignments` | list of `[user, role]` | — | One or more `[user, role]` pairs; each value may be a Go template |

**Assign roles (static):**

```yaml
steps:
  - type: step.authz_role_assign
    config:
      module: authz
      action: add                          # "add" (default) or "remove"
      assignments:
        - ["alice", "admin"]
        - ["bob", "editor"]
```

**Assign a role using templates** (values resolved from the pipeline context at runtime):

```yaml
steps:
  - type: step.authz_role_assign
    config:
      module: authz
      action: add
      assignments:
        - ["{{.new_user_id}}", "{{.tenant_role}}"]
```

**Revoke a role:**

```yaml
steps:
  - type: step.authz_role_assign
    config:
      module: authz
      action: remove
      assignments:
        - ["bob", "editor"]
```

On success the step outputs:

```json
{
  "authz_role_action": "add",
  "authz_role_assignments": [["alice", "admin"], ["bob", "editor"]]
}
```

## Build

```sh
make build   # outputs bin/workflow-plugin-authz
make test    # run tests with race detector
```

## Install

```sh
make install INSTALL_DIR=data/plugins/workflow-plugin-authz
```
