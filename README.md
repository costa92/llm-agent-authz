# llm-agent-authz

Shared, importable tenancy/auth library for the llm-agent ecosystem: org → parameterized scope, argon2id passwords, HS256 JWT access tokens, refresh-token sessions, and `Authenticate` / `RequireScopeRole` HTTP middleware. A **library, not a service** — consumers run its migrations, mount its handlers, and wrap routes with its middleware.

## Quick start (consumer)

```go
st := store.New(pool)
if err := st.Migrate(ctx); err != nil { /* ... */ }
iss := token.NewIssuer([]byte(secret), 15*time.Minute)
svc := service.New(st, iss, 30*24*time.Hour)

mux := http.NewServeMux()
httpapi.New(svc).Mount(mux, "/api/auth")

// Protect a kb route: require editor on the {kb} path scope.
guard := httpapi.RequireScopeRole(st, "kb", role.RoleEditor,
    func(r *http.Request) (string, string) { return orgFromCtx(r), r.PathValue("kb") })
mux.Handle("PUT /api/kb/{kb}/documents", httpapi.Authenticate(iss)(guard(docHandler)))
```

## Roles

`org_admin > admin > editor > viewer`. Effective role = highest of org-level (scope_id NULL) and scope-level membership. Cross-org access is denied (no membership → `RoleNone` → 403).

## Tests

Pure packages (`role`, `password`, `token`, `service`, `httpapi`) run with `go test ./...`. Store/integration tests need a Postgres DSN in `LLM_AGENT_AUTHZ_PG_URL` (skipped otherwise).

## Note

Standalone sibling repo of the llm-agent ecosystem; run Go commands with `GOWORK=off` unless added to the umbrella `go.work`.
