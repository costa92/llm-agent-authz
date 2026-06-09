package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const liveEnvVar = "LLM_AGENT_AUTHZ_PG_URL"

func openTestStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	dsn := os.Getenv(liveEnvVar)
	if dsn == "" {
		t.Skipf("set %s to run live postgres tests", liveEnvVar)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	s := New(pool)
	for _, tbl := range []string{"auth_session", "auth_membership", "auth_user", "auth_org"} {
		_, _ = pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl+" CASCADE")
	}
	_, _ = pool.Exec(ctx, "DROP TABLE IF EXISTS authz_schema_version")
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM auth_user").Scan(&n); err != nil {
		t.Fatalf("auth_user not queryable after migrate: %v", err)
	}
}

func TestCreateAndGetUser(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	id, err := s.CreateUser(ctx, "Alice@Example.com", "phc-hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u.ID != id || u.Email != "alice@example.com" || u.PasswordHash != "phc-hash" {
		t.Fatalf("user mismatch: %+v", u)
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	if _, err := s.CreateUser(ctx, "dup@x.com", "h"); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := s.CreateUser(ctx, "DUP@x.com", "h"); err == nil {
		t.Fatal("duplicate email (case-insensitive) must error")
	}
}

func TestGetUserMissing(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	if _, err := s.GetUserByEmail(ctx, "nobody@x.com"); err != ErrNotFound {
		t.Fatalf("missing user err=%v, want ErrNotFound", err)
	}
}
