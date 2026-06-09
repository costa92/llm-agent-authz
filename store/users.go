package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrNotFound = errors.New("authz: not found")

type User struct {
	ID           string
	Email        string
	PasswordHash string
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
		return "", err
	}
	return id, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash FROM auth_user WHERE email = $1`,
		normalizeEmail(email)).Scan(&u.ID, &u.Email, &u.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateOrg(ctx context.Context, name string) (string, error) {
	id := newID()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO auth_org (id, name) VALUES ($1, $2)`, id, name); err != nil {
		return "", err
	}
	return id, nil
}
