package auth

import (
	"crypto/rand"
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
	EnvAuthToken          = "FCP_AUTH_TOKEN"              //nolint:gosec // Environment variable name, not a credential value.
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
	return token, nil
}

func WriteTokenFile(path, token string) error {
	if !ValidateTokenFormat(token) {
		return fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil { //nolint:gosec // 0600 is the intended restrictive token-file permission.
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

func ResolveToken(cliToken, cliTokenFile, defaultFile string) (string, error) {
	if strings.TrimSpace(cliToken) != "" {
		token := strings.TrimSpace(cliToken)
		if !ValidateTokenFormat(token) {
			log.Warn("invalid CLI token format", "length", len(token))
			return "", fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
		}
		log.Debug("token resolved from CLI flag")
		return token, nil
	}
	if strings.TrimSpace(cliTokenFile) != "" {
		log.Debug("reading token from CLI token file", "path", cliTokenFile)
		return ReadTokenFile(cliTokenFile)
	}
	if token := strings.TrimSpace(os.Getenv(EnvAuthToken)); token != "" {
		if !ValidateTokenFormat(token) {
			log.Warn("invalid env token format", "length", len(token))
			return "", fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidToken, TokenHexLength, len(token))
		}
		log.Debug("token resolved from env", "env", EnvAuthToken)
		return token, nil
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

func ResolveCLIToken(cliToken, cliTokenFile string) string {
	defaultFile, err := TokenFilePath()
	if err != nil {
		return ""
	}
	token, err := ResolveToken(cliToken, cliTokenFile, defaultFile)
	if err != nil {
		return ""
	}
	return token
}
