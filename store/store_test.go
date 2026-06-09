package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/costa92/llm-agent-authz/role"
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

func seedUserOrg(t *testing.T, ctx context.Context, s *Store) (uid, oid string) {
	t.Helper()
	uid, err := s.CreateUser(ctx, newID()+"@x.com", "h")
	if err != nil {
		t.Fatal(err)
	}
	oid, err = s.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	return uid, oid
}

func TestResolveRoleMergesOrgAndScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	uid, oid := seedUserOrg(t, ctx, s)
	if err := s.UpsertMembership(ctx, oid, uid, "kb", nil, role.RoleEditor); err != nil {
		t.Fatal(err)
	}
	kb := "kb-1"
	if err := s.UpsertMembership(ctx, oid, uid, "kb", &kb, role.RoleViewer); err != nil {
		t.Fatal(err)
	}
	got, err := s.ResolveRole(ctx, uid, oid, "kb", "kb-1")
	if err != nil || got != role.RoleEditor {
		t.Fatalf("ResolveRole=%q,%v want editor", got, err)
	}
}

func TestResolveRoleNoMembershipIsNone(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	uid, oid := seedUserOrg(t, ctx, s)
	got, err := s.ResolveRole(ctx, uid, oid, "kb", "kb-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != role.RoleNone {
		t.Fatalf("no membership should resolve to none, got %q", got)
	}
}

func TestResolveRoleScopeIsolated(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	uid, oid := seedUserOrg(t, ctx, s)
	kbA := "kb-A"
	if err := s.UpsertMembership(ctx, oid, uid, "kb", &kbA, role.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ResolveRole(ctx, uid, oid, "kb", "kb-B")
	if got != role.RoleNone {
		t.Fatalf("admin on kb-A leaked to kb-B: %q", got)
	}
}

func TestUpsertMembershipReplacesRole(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, ctx)
	uid, oid := seedUserOrg(t, ctx, s)
	kb := "kb-1"
	_ = s.UpsertMembership(ctx, oid, uid, "kb", &kb, role.RoleViewer)
	if err := s.UpsertMembership(ctx, oid, uid, "kb", &kb, role.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ResolveRole(ctx, uid, oid, "kb", "kb-1")
	if got != role.RoleAdmin {
		t.Fatalf("upsert should replace role, got %q", got)
	}
}
