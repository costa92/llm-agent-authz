package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrNotFound = errors.New("authz: not found")

var ErrConflict = errors.New("authz: conflict")

type User struct {
	ID                    string
	Email                 string
	PasswordHash          string
	IsVerified            bool
	VerificationCode      string
	VerificationExpiresAt *time.Time
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *Store) CreateUser(ctx context.Context, email, passwordHash string) (string, error) {
	id := newID()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_user (id, email, password_hash) VALUES ($1, $2, $3)`,
		id, normalizeEmail(email), passwordHash)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", ErrConflict
		}
		return "", err
	}
	return id, nil
}

// GetUserByEmail looks up a live (not soft-deleted) user by email. The
// `deleted_at IS NULL` guard is load-bearing: it is what blocks a soft-deleted
// account from logging in (Service.Login resolves the user through here) — a
// retired account becomes ErrNotFound, indistinguishable from never having
// existed.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, is_verified, verification_code, verification_expires_at
		 FROM auth_user WHERE email = $1 AND deleted_at IS NULL`,
		normalizeEmail(email)).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsVerified, &u.VerificationCode, &u.VerificationExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// SoftDeleteUser retires a user: it stamps deleted_at (so GetUserByEmail can no
// longer find them → login blocked) and revokes all their refresh sessions (so an
// outstanding refresh cookie cannot mint a new session). The row and its FK
// children (memberships, sessions) are preserved for audit and to keep
// created-by lineage resolvable. Already-issued ACCESS tokens remain valid until
// they expire (≤ access TTL) — the standard stateless-JWT residual window.
//
// Idempotent-ish: a user that does not exist or is already soft-deleted returns
// ErrNotFound (0 rows matched the `deleted_at IS NULL` guard).
func (s *Store) SoftDeleteUser(ctx context.Context, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE auth_user SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetUserVerificationCode(ctx context.Context, email, code string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth_user
		SET is_verified = false, verification_code = $2, verification_expires_at = $3
		WHERE email = $1`, normalizeEmail(email), code, expiresAt)
	return err
}

func (s *Store) VerifyUserCode(ctx context.Context, email, code string, now time.Time) (bool, error) {
	var dbCode string
	var dbExpires *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT verification_code, verification_expires_at FROM auth_user
		WHERE email = $1`, normalizeEmail(email)).Scan(&dbCode, &dbExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if dbCode == "" || dbCode != code {
		return false, nil
	}
	if dbExpires != nil && now.After(*dbExpires) {
		return false, nil
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE auth_user
		SET is_verified = true, verification_code = '', verification_expires_at = NULL
		WHERE email = $1`, normalizeEmail(email))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) CreateOrg(ctx context.Context, name string) (string, error) {
	id := newID()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO auth_org (id, name) VALUES ($1, $2)`, id, name); err != nil {
		return "", err
	}
	return id, nil
}

// SetPassword updates the password hash for the given user ID.
// If the user does not exist, it returns ErrNotFound.
func (s *Store) SetPassword(ctx context.Context, userID, passwordHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_user SET password_hash = $2 WHERE id = $1`,
		userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
