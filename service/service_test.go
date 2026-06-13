package service

import (
	"context"
	"testing"
	"time"

	"github.com/costa92/llm-agent-authz/password"
	"github.com/costa92/llm-agent-authz/store"
	"github.com/costa92/llm-agent-authz/token"
)

type fakeStore struct {
	users    map[string]store.User // by email
	sessions map[string]string     // refresh_hash -> userID (live only)
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[string]store.User{}, sessions: map[string]string{}}
}
func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (store.User, error) {
	u, ok := f.users[email]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}
func (f *fakeStore) CreateSession(_ context.Context, userID, hash, _ string, _ time.Time) error {
	f.sessions[hash] = userID
	return nil
}
func (f *fakeStore) SessionByHash(_ context.Context, hash string) (store.Session, error) {
	uid, ok := f.sessions[hash]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return store.Session{UserID: uid, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (f *fakeStore) RotateSession(_ context.Context, oldHash, newHash string, _ time.Time) error {
	uid, ok := f.sessions[oldHash]
	if !ok {
		return store.ErrNotFound
	}
	delete(f.sessions, oldHash)
	f.sessions[newHash] = uid
	return nil
}
func (f *fakeStore) RevokeSession(_ context.Context, hash string) error {
	delete(f.sessions, hash)
	return nil
}
func (f *fakeStore) RevokeAllForUser(_ context.Context, userID string) error {
	for h, u := range f.sessions {
		if u == userID {
			delete(f.sessions, h)
		}
	}
	return nil
}

func newSvc(t *testing.T) (*Service, *fakeStore) {
	t.Helper()
	fs := newFakeStore()
	hash, _ := password.Hash("pw")
	fs.users["alice@x.com"] = store.User{ID: "u1", Email: "alice@x.com", PasswordHash: hash, IsVerified: true}
	svc := New(fs, token.NewIssuer([]byte("sec"), 15*time.Minute), 30*24*time.Hour)
	return svc, fs
}

func TestLoginSuccess(t *testing.T) {
	svc, _ := newSvc(t)
	res, err := svc.Login(context.Background(), "alice@x.com", "pw", "agent")
	if err != nil || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("Login=%+v,%v", res, err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Login(context.Background(), "alice@x.com", "nope", ""); err != ErrInvalidCredentials {
		t.Fatalf("err=%v want ErrInvalidCredentials", err)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Login(context.Background(), "ghost@x.com", "pw", ""); err != ErrInvalidCredentials {
		t.Fatalf("err=%v want ErrInvalidCredentials", err)
	}
}

func TestRefreshRotates(t *testing.T) {
	svc, _ := newSvc(t)
	first, _ := svc.Login(context.Background(), "alice@x.com", "pw", "")
	second, err := svc.Refresh(context.Background(), first.RefreshToken)
	if err != nil || second.RefreshToken == first.RefreshToken {
		t.Fatalf("Refresh did not rotate: %+v,%v", second, err)
	}
	if _, err := svc.Refresh(context.Background(), first.RefreshToken); err == nil {
		t.Fatal("reused old refresh token must fail")
	}
}
