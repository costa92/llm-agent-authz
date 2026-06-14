// Package httpapi exposes auth HTTP handlers and middleware for consumers to mount.
package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/costa92/llm-agent-authz/role"
	"github.com/costa92/llm-agent-authz/token"
)

type ctxUserKey struct{}

// UserID returns the authenticated user id stored by Authenticate, or "".
func UserID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxUserKey{}).(string); ok {
		return v
	}
	return ""
}

// Authenticate validates the Bearer access token and stores the user id in ctx.
func Authenticate(iss *token.Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			tok, ok := strings.CutPrefix(authz, "Bearer ")
			if !ok || tok == "" {
				tok = r.URL.Query().Get("token")
				if tok == "" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			uid, err := iss.Verify(tok)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, uid)))
		})
	}
}

// RoleResolver is satisfied by *store.Store.
type RoleResolver interface {
	ResolveRole(ctx context.Context, userID, orgID, scopeKind, scopeID string) (role.Role, error)
}

// ScopeFromRequest extracts (orgID, scopeID) from the request (e.g. path values).
type ScopeFromRequest func(r *http.Request) (orgID, scopeID string)

// RequireScopeRole enforces that the authenticated user has at least `min` role
// in the (scopeKind, scopeID) resolved from the request. 401 if unauthenticated,
// 403 if insufficient.
func RequireScopeRole(res RoleResolver, scopeKind string, min role.Role, scope ScopeFromRequest) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid := UserID(r.Context())
			if uid == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			orgID, scopeID := scope(r)
			eff, err := res.ResolveRole(r.Context(), uid, orgID, scopeKind, scopeID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !eff.AtLeast(min) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
