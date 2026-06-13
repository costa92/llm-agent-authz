package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/costa92/llm-agent-authz/service"
)

const refreshCookieName = "authz_refresh"

// AuthService is the slice of service.Service the handlers need (fake-able in tests).
type AuthService interface {
	Login(ctx context.Context, email, password, userAgent string) (service.LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (service.LoginResult, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID string) error
}

type Handlers struct{ svc AuthService }

func New(svc AuthService) *Handlers { return &Handlers{svc: svc} }

// Mount registers the auth routes under prefix (e.g. "/api/auth") on mux.
func (h *Handlers) Mount(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"/login", h.login)
	mux.HandleFunc("POST "+prefix+"/refresh", h.refresh)
	mux.HandleFunc("POST "+prefix+"/logout", h.logout)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func setRefreshCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: refreshCookieName, Value: value, Path: "/api/auth",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := h.svc.Login(r.Context(), req.Email, req.Password, r.UserAgent())
	if errors.Is(err, service.ErrInvalidCredentials) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, service.ErrEmailNotVerified) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verified": false,
			"email":    req.Email,
			"error":    "email not verified",
		})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, res.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": res.AccessToken, "expires_in": res.ExpiresIn})
}

// requireCSRF enforces a double-submit header on cookie-driven endpoints.
func requireCSRF(r *http.Request) bool { return r.Header.Get("X-CSRF") == "1" }

func (h *Handlers) refresh(w http.ResponseWriter, r *http.Request) {
	if !requireCSRF(r) {
		http.Error(w, "missing csrf header", http.StatusForbidden)
		return
	}
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	res, err := h.svc.Refresh(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	setRefreshCookie(w, res.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": res.AccessToken, "expires_in": res.ExpiresIn})
}

func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	if !requireCSRF(r) {
		http.Error(w, "missing csrf header", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(refreshCookieName); err == nil {
		_ = h.svc.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: "", Path: "/api/auth", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
