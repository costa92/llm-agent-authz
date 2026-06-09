package password

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	enc, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Fatalf("encoded form not PHC argon2id: %q", enc)
	}
	ok, err := Verify("correct horse battery staple", enc)
	if err != nil || !ok {
		t.Fatalf("Verify(correct)=%v,%v want true,nil", ok, err)
	}
	ok, err = Verify("wrong", enc)
	if err != nil || ok {
		t.Fatalf("Verify(wrong)=%v,%v want false,nil", ok, err)
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	if _, err := Verify("x", "not-a-phc-string"); err == nil {
		t.Fatal("Verify of malformed encoded string must error")
	}
}
