# workflow-plugin-authz

RBAC authorization plugin for the [workflow engine](https://github.com/GoCodeAlone/workflow) using [Casbin](https://casbin.org/).

## Capabilities

| Type | Name |
|---|---|
| Module | `authz.casbin` |
| Step | `step.authz_check` |

## authz.casbin module

Loads a Casbin PERM model and policy from inline YAML config. The enforcer is thread-safe and shared with all `step.authz_check` steps that reference the module by name.

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

## step.authz_check pipeline step

Checks whether the authenticated user (injected by `step.auth_required`) has permission to perform the configured action on the configured object. Returns HTTP 403 and stops the pipeline on denial.

```yaml
steps:
  - type: step.auth_required   # sets auth_user_id in output
    config: {}

  - type: step.authz_check
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

## Build

```sh
make build   # outputs bin/workflow-plugin-authz
make test    # run tests with race detector
```

## Install

```sh
make install INSTALL_DIR=data/plugins/workflow-plugin-authz
```
