package store

import (
	"context"
	"fmt"
)

// HeadSchemaVersion is the latest schema version this code migrates to.
const HeadSchemaVersion = 1

type migrationGroup struct {
	Version    int
	Statements []string
}

func migrations() []migrationGroup {
	return []migrationGroup{
		{Version: 1, Statements: []string{
			`CREATE TABLE IF NOT EXISTS auth_org (
				id          TEXT PRIMARY KEY,
				name        TEXT NOT NULL,
				created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE TABLE IF NOT EXISTS auth_user (
				id            TEXT PRIMARY KEY,
				email         TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE TABLE IF NOT EXISTS auth_membership (
				org_id     TEXT NOT NULL REFERENCES auth_org(id) ON DELETE CASCADE,
				user_id    TEXT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
				scope_kind TEXT NOT NULL,
				scope_id   TEXT,
				role       TEXT NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS auth_membership_uniq
				ON auth_membership (org_id, user_id, scope_kind, COALESCE(scope_id, ''))`,
			`CREATE TABLE IF NOT EXISTS auth_session (
				id           TEXT PRIMARY KEY,
				user_id      TEXT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
				refresh_hash TEXT NOT NULL UNIQUE,
				user_agent   TEXT NOT NULL DEFAULT '',
				expires_at   TIMESTAMPTZ NOT NULL,
				revoked_at   TIMESTAMPTZ,
				created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE INDEX IF NOT EXISTS auth_session_user ON auth_session (user_id)`,
		}},
	}
}

func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS authz_schema_version (version INT PRIMARY KEY)`); err != nil {
		return fmt.Errorf("authz: ensure version table: %w", err)
	}
	var current int
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) FROM authz_schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("authz: read schema version: %w", err)
	}
	for _, g := range migrations() {
		if g.Version <= current {
			continue
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		for _, stmt := range g.Statements {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("authz: migrate v%d: %w", g.Version, err)
			}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO authz_schema_version(version) VALUES ($1) ON CONFLICT (version) DO NOTHING`, g.Version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
