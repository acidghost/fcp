package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/acidghost/fcp/internal/log"
)

const (
	TokenHexLength        = 64
	TokenByteLength       = 32
	EnvAuthTokenFile      = "FCP_AUTH_TOKEN_FILE"         //nolint:gosec // Environment variable name, not a credential value.
	DefaultContainerToken = "/run/secrets/fcp-auth-token" //nolint:gosec // Default token file path, not a credential value.
	configDirName         = "fcp"
	tokenFileName         = "auth-token"
)

var (
	ErrNoTokenSource = errors.New("no auth token source")
	ErrTokenNotFound = errors.New("auth token file not found")
	ErrInvalidToken  = errors.New("invalid auth token")
)

func TokenFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", configDirName, tokenFileName), nil
}

func ValidateTokenFormat(token string) bool {
	if len(token) != TokenHexLength {
		return false
	}
	for _, r := range token {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func NormalizeToken(token string) string {
	return strings.ToLower(strings.TrimSpace(token))
}

func CompareTokens(expected, candidate string) bool {
	expected = NormalizeToken(expected)
	candidate = NormalizeToken(candidate)
	if !ValidateTokenFormat(expected) || !ValidateTokenFormat(candidate) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1
}

func DataHandshakeProof(token, connID string) (string, error) {
	token = NormalizeToken(token)
	if !ValidateTokenFormat(token) {
		return "", fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
	}
	key, err := hex.DecodeString(token)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(connID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyDataHandshakeProof(token, connID, proof string) bool {
	expected, err := DataHandshakeProof(token, connID)
	if err != nil {
		return false
	}
	proof = NormalizeToken(proof)
	if !ValidateTokenFormat(proof) {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(proof))
}

func GenerateToken() (string, error) {
	buf := make([]byte, TokenByteLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func ReadTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // The user explicitly configures the token file path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrTokenNotFound, path)
		}
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if !ValidateTokenFormat(token) {
		return "", fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
	}
	return NormalizeToken(token), nil
}

func WriteTokenFile(path, token string) error {
	token = NormalizeToken(token)
	if !ValidateTokenFormat(token) {
		return fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil { //nolint:gosec // 0600 is the intended restrictive token-file permission.
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}

func EnsureToken(path string) (string, error) {
	token, err := ReadTokenFile(path)
	if err == nil {
		log.Debug("existing token loaded from file", "path", path)
		return token, nil
	}
	if !errors.Is(err, ErrTokenNotFound) {
		return "", err
	}
	log.Info("generating new auth token", "path", path)
	token, err = GenerateToken()
	if err != nil {
		return "", err
	}
	if err := WriteTokenFile(path, token); err != nil {
		return "", err
	}
	log.Info("auth token written to file", "path", path)
	return token, nil
}

func ResolveToken(cliTokenFile, defaultFile string) (string, error) {
	if strings.TrimSpace(cliTokenFile) != "" {
		log.Debug("reading token from CLI token file", "path", cliTokenFile)
		return ReadTokenFile(cliTokenFile)
	}
	if path := strings.TrimSpace(os.Getenv(EnvAuthTokenFile)); path != "" {
		log.Debug("reading token from env token file", "path", path)
		return ReadTokenFile(path)
	}
	if defaultFile != "" {
		token, err := ReadTokenFile(defaultFile)
		if err == nil {
			log.Debug("token resolved from default file", "path", defaultFile)
			return token, nil
		}
		if !errors.Is(err, ErrTokenNotFound) {
			return "", err
		}
		log.Debug("default token file not found", "path", defaultFile)
	}
	log.Warn("no auth token source found")
	return "", fmt.Errorf("%w: checked %s", ErrNoTokenSource, defaultFile)
}

func ResolveCLIToken(cliTokenFile string) string {
	defaultFile, err := TokenFilePath()
	if err != nil {
		return ""
	}
	token, err := ResolveToken(cliTokenFile, defaultFile)
	if err != nil {
		return ""
	}
	return token
}

func ResolveClientToken(cliTokenFile string) (string, error) {
	token, err := ResolveToken(cliTokenFile, DefaultContainerToken)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, ErrNoTokenSource) {
		return "", err
	}

	defaultFile, pathErr := TokenFilePath()
	if pathErr != nil {
		return "", pathErr
	}
	token, err = ResolveToken(cliTokenFile, defaultFile)
	if err == nil {
		return token, nil
	}
	if errors.Is(err, ErrNoTokenSource) {
		return "", fmt.Errorf("%w: no fcp auth token found; set %s, mount %s, or copy %s into the container", ErrNoTokenSource, EnvAuthTokenFile, DefaultContainerToken, defaultFile)
	}
	return "", err
}
