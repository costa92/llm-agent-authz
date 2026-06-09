package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/costa92/llm-agent-authz/role"
	"github.com/costa92/llm-agent-authz/service"
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

type fakeAuth struct {
	loginRes   service.LoginResult
	loginErr   error
	refreshRes service.LoginResult
	refreshErr error
	loggedOut  bool
}

func (f *fakeAuth) Login(_ context.Context, email, pw, ua string) (service.LoginResult, error) {
	return f.loginRes, f.loginErr
}
func (f *fakeAuth) Refresh(_ context.Context, rt string) (service.LoginResult, error) {
	return f.refreshRes, f.refreshErr
}
func (f *fakeAuth) Logout(_ context.Context, rt string) error { f.loggedOut = true; return nil }
func (f *fakeAuth) LogoutAll(_ context.Context, uid string) error { return nil }

func TestLoginHandlerSetsCookieAndReturnsAccess(t *testing.T) {
	fa := &fakeAuth{loginRes: service.LoginResult{AccessToken: "acc", RefreshToken: "ref", ExpiresIn: 900}}
	h := New(fa)
	mux := http.NewServeMux()
	h.Mount(mux, "/api/auth")
	body := strings.NewReader(`{"email":"a@x.com","password":"pw"}`)
	req := httptest.NewRequest("POST", "/api/auth/login", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["access_token"] != "acc" {
		t.Fatalf("access_token=%v", out["access_token"])
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("refresh cookie not httpOnly: %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestLoginHandlerInvalidCreds401(t *testing.T) {
	fa := &fakeAuth{loginErr: service.ErrInvalidCredentials}
	h := New(fa)
	mux := http.NewServeMux()
	h.Mount(mux, "/api/auth")
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email":"a@x.com","password":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestRefreshRequiresCSRFHeader(t *testing.T) {
	fa := &fakeAuth{refreshRes: service.LoginResult{AccessToken: "acc2", RefreshToken: "ref2", ExpiresIn: 900}}
	h := New(fa)
	mux := http.NewServeMux()
	h.Mount(mux, "/api/auth")
	req := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "ref"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("refresh without CSRF code=%d want 403", rec.Code)
	}
}
