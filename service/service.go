// Package service orchestrates login/refresh/logout over store+password+token.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/costa92/llm-agent-authz/password"
	"github.com/costa92/llm-agent-authz/store"
	"github.com/costa92/llm-agent-authz/token"
)

// ErrInvalidCredentials is returned for both unknown user and wrong password
// (no account enumeration).
var ErrInvalidCredentials = errors.New("authz: invalid credentials")

// Store is the persistence slice the service needs (satisfied by *store.Store).
type Store interface {
	GetUserByEmail(ctx context.Context, email string) (store.User, error)
	CreateSession(ctx context.Context, userID, refreshHash, userAgent string, expiresAt time.Time) error
	SessionByHash(ctx context.Context, refreshHash string) (store.Session, error)
	RotateSession(ctx context.Context, oldHash, newHash string, newExpiry time.Time) error
	RevokeSession(ctx context.Context, refreshHash string) error
	RevokeAllForUser(ctx context.Context, userID string) error
}

type Service struct {
	store      Store
	issuer     *token.Issuer
	refreshTTL time.Duration
}

func New(s Store, issuer *token.Issuer, refreshTTL time.Duration) *Service {
	return &Service{store: s, issuer: issuer, refreshTTL: refreshTTL}
}

// LoginResult carries the freshly minted tokens. RefreshToken is the opaque
// secret to set as an httpOnly cookie; only its hash is persisted.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // access token TTL seconds
}

func newRefreshToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func (s *Service) Login(ctx context.Context, email, plain, userAgent string) (LoginResult, error) {
	u, err := s.store.GetUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}
	ok, err := password.Verify(plain, u.PasswordHash)
	if err != nil || !ok {
		return LoginResult{}, ErrInvalidCredentials
	}
	return s.issue(ctx, u.ID, userAgent)
}

func (s *Service) issue(ctx context.Context, userID, userAgent string) (LoginResult, error) {
	now := time.Now()
	access, err := s.issuer.Issue(userID, now)
	if err != nil {
		return LoginResult{}, err
	}
	refresh := newRefreshToken()
	if err := s.store.CreateSession(ctx, userID, hashToken(refresh), userAgent, now.Add(s.refreshTTL)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{AccessToken: access, RefreshToken: refresh, ExpiresIn: 900}, nil
}

// Refresh rotates the refresh token (old becomes invalid) and mints a new access token.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (LoginResult, error) {
	sess, err := s.store.SessionByHash(ctx, hashToken(refreshToken))
	if errors.Is(err, store.ErrNotFound) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}
	now := time.Now()
	access, err := s.issuer.Issue(sess.UserID, now)
	if err != nil {
		return LoginResult{}, err
	}
	newRefresh := newRefreshToken()
	if err := s.store.RotateSession(ctx, hashToken(refreshToken), hashToken(newRefresh), now.Add(s.refreshTTL)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{AccessToken: access, RefreshToken: newRefresh, ExpiresIn: 900}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.store.RevokeSession(ctx, hashToken(refreshToken))
}

func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	return s.store.RevokeAllForUser(ctx, userID)
}
