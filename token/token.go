// Package token issues and verifies short-lived HS256 JWT access tokens.
// Pure: no I/O. Time is injectable for deterministic tests.
package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	secret    []byte
	accessTTL time.Duration
}

func NewIssuer(secret []byte, accessTTL time.Duration) *Issuer {
	return &Issuer{secret: secret, accessTTL: accessTTL}
}

// Issue mints an access token for userID, valid for accessTTL from now.
func (i *Issuer) Issue(userID string, now time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(i.accessTTL)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
}

// VerifyAt validates the token as of `now` and returns the subject (user id).
func (i *Issuer) VerifyAt(tok string, now time.Time) (string, error) {
	parsed, err := jwt.Parse(tok, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("authz: unexpected signing method")
		}
		return i.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return "", err
	}
	sub, err := parsed.Claims.GetSubject()
	if err != nil || sub == "" {
		return "", errors.New("authz: token missing subject")
	}
	return sub, nil
}

// Verify validates as of the current wall clock.
func (i *Issuer) Verify(tok string) (string, error) { return i.VerifyAt(tok, time.Now()) }
