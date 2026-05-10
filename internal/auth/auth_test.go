package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateTokenFormatAndUniqueness(t *testing.T) {
	one, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	two, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("GenerateToken produced duplicate tokens")
	}
	if !ValidateTokenFormat(one) || !ValidateTokenFormat(two) {
		t.Fatalf("generated tokens are not valid: %q %q", one, two)
	}
}

func TestEnsureTokenCreatesAndReusesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-token")
	one, err := EnsureToken(path)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EnsureToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("EnsureToken did not reuse file: %q != %q", one, two)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 0600", info.Mode().Perm())
	}
}
