package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/costa92/llm-agent-authz/role"
	"github.com/costa92/llm-agent-authz/token"
)

type fakeResolver struct{ roles map[string]role.Role } // key: scopeID

func (f fakeResolver) ResolveRole(_ context.Context, _, _, _, scopeID string) (role.Role, error) {
	return f.roles[scopeID], nil
}

func TestAuthenticateRejectsMissingToken(t *testing.T) {
	iss := token.NewIssuer([]byte("s"), time.Minute)
	h := Authenticate(iss)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run without token")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestAuthenticatePassesUserID(t *testing.T) {
	iss := token.NewIssuer([]byte("s"), time.Minute)
	tok, _ := iss.Issue("u1", time.Now())
	var seen string
	h := Authenticate(iss)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserID(r.Context())
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "u1" {
		t.Fatalf("UserID in ctx=%q want u1", seen)
	}
}

func TestRequireScopeRoleForbidsInsufficient(t *testing.T) {
	res := fakeResolver{roles: map[string]role.Role{"kb-1": role.RoleViewer}}
	mw := RequireScopeRole(res, "kb", role.RoleEditor, func(r *http.Request) (string, string) {
		return "org-1", r.PathValue("kb")
	})
	h := withUser("u1", mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for viewer when editor required")
	})))
	mux := http.NewServeMux()
	mux.Handle("/kb/{kb}", h)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/kb/kb-1", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", rec.Code)
	}
}

func TestRequireScopeRoleAllowsSufficient(t *testing.T) {
	res := fakeResolver{roles: map[string]role.Role{"kb-1": role.RoleAdmin}}
	mw := RequireScopeRole(res, "kb", role.RoleEditor, func(r *http.Request) (string, string) {
		return "org-1", r.PathValue("kb")
	})
	ran := false
	h := withUser("u1", mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran = true })))
	mux := http.NewServeMux()
	mux.Handle("/kb/{kb}", h)
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/kb/kb-1", nil))
	if !ran {
		t.Fatal("handler should run for admin when editor required")
	}
}

// withUser injects a user id into the context (test helper mimicking Authenticate).
func withUser(uid string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, uid)))
	})
}
