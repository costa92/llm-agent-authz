// Package store is the pgx-backed persistence layer for llm-agent-authz:
// users, orgs, memberships, and refresh sessions, plus versioned migrations.
package store

import "github.com/jackc/pgx/v5/pgxpool"

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }
