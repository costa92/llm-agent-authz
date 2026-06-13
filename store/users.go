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

func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, is_verified, verification_code, verification_expires_at FROM auth_user WHERE email = $1`,
		normalizeEmail(email)).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsVerified, &u.VerificationCode, &u.VerificationExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
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

