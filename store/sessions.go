package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

func (s *Store) CreateSession(ctx context.Context, userID, refreshHash, userAgent string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_session (id, user_id, refresh_hash, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		newID(), userID, refreshHash, userAgent, expiresAt)
	return err
}

func (s *Store) SessionByHash(ctx context.Context, refreshHash string) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, expires_at, revoked_at FROM auth_session
		 WHERE refresh_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		refreshHash).Scan(&sess.ID, &sess.UserID, &sess.ExpiresAt, &sess.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

func (s *Store) RotateSession(ctx context.Context, oldHash, newHash string, newExpiry time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID string
	err = tx.QueryRow(ctx,
		`UPDATE auth_session SET revoked_at = now()
		 WHERE refresh_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		 RETURNING user_id`, oldHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO auth_session (id, user_id, refresh_hash, expires_at)
		 VALUES ($1, $2, $3, $4)`, newID(), userID, newHash, newExpiry); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeSession(ctx context.Context, refreshHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE auth_session SET revoked_at = now() WHERE refresh_hash = $1 AND revoked_at IS NULL`,
		refreshHash)
	return err
}

func (s *Store) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE auth_session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID)
	return err
}
