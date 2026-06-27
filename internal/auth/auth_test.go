package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestTokenNormalizationAndCompare(t *testing.T) {
	lower := strings.Repeat("a", TokenHexLength)
	upper := strings.ToUpper(lower)
	if NormalizeToken(" "+upper+"\n") != lower {
		t.Fatal("NormalizeToken did not trim and lowercase token")
	}
	if !CompareTokens(lower, upper) {
		t.Fatal("CompareTokens rejected equivalent hex token")
	}
	if CompareTokens(lower, strings.Repeat("b", TokenHexLength)) {
		t.Fatal("CompareTokens accepted a different token")
	}
	if CompareTokens(lower, "not-a-token") {
		t.Fatal("CompareTokens accepted malformed token")
	}
}

func TestDataHandshakeProof(t *testing.T) {
	token := strings.Repeat("d", TokenHexLength)
	proof, err := DataHandshakeProof(token, "conn-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTokenFormat(proof) {
		t.Fatalf("proof is not 64 hex chars: %q", proof)
	}
	if !VerifyDataHandshakeProof(strings.ToUpper(token), "conn-1", strings.ToUpper(proof)) {
		t.Fatal("VerifyDataHandshakeProof rejected valid proof")
	}
	if VerifyDataHandshakeProof(token, "conn-2", proof) {
		t.Fatal("VerifyDataHandshakeProof accepted proof for different connID")
	}
	if VerifyDataHandshakeProof(token, "conn-1", strings.Repeat("e", TokenHexLength)) {
		t.Fatal("VerifyDataHandshakeProof accepted wrong proof")
	}
}

func TestResolveClientTokenFallsBackToHostDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvAuthToken, "")
	t.Setenv(EnvAuthTokenFile, "")

	path := filepath.Join(home, ".config", configDirName, tokenFileName)
	token := strings.Repeat("e", TokenHexLength)
	if err := WriteTokenFile(path, token); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveClientToken("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("ResolveClientToken() = %q, want %q", got, token)
	}
}

func TestResolveClientTokenErrorsWhenNoSource(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvAuthToken, "")
	t.Setenv(EnvAuthTokenFile, "")
	if _, err := ResolveClientToken("", ""); !errors.Is(err, ErrNoTokenSource) {
		t.Fatalf("ResolveClientToken() err = %v, want ErrNoTokenSource", err)
	}
}

func TestReadAndWriteTokenFileNormalizeAndRepairMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-token")
	token := strings.ToUpper(strings.Repeat("c", TokenHexLength))
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil { //nolint:gosec // This test verifies WriteTokenFile repairs overly permissive file modes.
		t.Fatal(err)
	}
	if err := WriteTokenFile(path, token); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ToLower(token) {
		t.Fatalf("ReadTokenFile() = %q, want normalized token", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 0600", info.Mode().Perm())
	}
}
