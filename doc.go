// Package authz is the umbrella module for llm-agent-authz: a shared,
// importable tenancy/auth library (org -> parameterized scope) providing
// argon2id passwords, JWT access tokens, refresh-token sessions, and
// Authenticate / RequireScopeRole HTTP middleware. It is a library, not a
// service: consuming services run its migrations, mount its handlers, and
// wrap routes with its middleware.
package authz
