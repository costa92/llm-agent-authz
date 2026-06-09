package token

import (
	"testing"
	"time"
)

func TestIssueVerifyRoundTrip(t *testing.T) {
	iss := NewIssuer([]byte("test-secret"), 15*time.Minute)
	tok, err := iss.Issue("user-123", time.Unix(1_000_000, 0))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	uid, err := iss.VerifyAt(tok, time.Unix(1_000_100, 0))
	if err != nil || uid != "user-123" {
		t.Fatalf("VerifyAt=%q,%v want user-123,nil", uid, err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss := NewIssuer([]byte("test-secret"), 1*time.Minute)
	tok, _ := iss.Issue("u", time.Unix(1_000_000, 0))
	if _, err := iss.VerifyAt(tok, time.Unix(1_000_000+120, 0)); err == nil {
		t.Fatal("expired token must fail verification")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	tok, _ := NewIssuer([]byte("secret-a"), time.Minute).Issue("u", time.Unix(1_000_000, 0))
	if _, err := NewIssuer([]byte("secret-b"), time.Minute).VerifyAt(tok, time.Unix(1_000_001, 0)); err == nil {
		t.Fatal("token signed with different secret must fail")
	}
}
