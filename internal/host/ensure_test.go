package host

import (
	"context"
	"strings"
	"testing"

	"github.com/acidghost/fcp/internal/auth"
)

func TestHostDaemonCommandPassesTokenFileInArgv(t *testing.T) {
	tokenFile := "/tmp/fcp-auth-token" //nolint:gosec // Test fixture path, not a credential value.

	cmd := hostDaemonCommand(context.Background(), "/usr/local/bin/fcp", 19285, 19286, false, false, tokenFile, "/tmp/fcp.log")

	if hasArg(cmd.Args, "--auth-token") {
		t.Fatalf("argv contains --auth-token: %#v", cmd.Args)
	}
	if !hasArgValue(cmd.Args, "--auth-token-file", tokenFile) {
		t.Fatalf("argv missing token file %q: %#v", tokenFile, cmd.Args)
	}
	if !hasArg(cmd.Args, "--log-file") {
		t.Fatalf("argv missing --log-file: %#v", cmd.Args)
	}
	if cmd.Env != nil {
		t.Fatalf("command env = %#v, want nil", cmd.Env)
	}
}

func TestHostDaemonCommandNoAuthDoesNotPassToken(t *testing.T) {
	token := strings.Repeat("b", auth.TokenHexLength)

	cmd := hostDaemonCommand(context.Background(), "/usr/local/bin/fcp", 19285, 19286, true, false, "/tmp/fcp-auth-token", "")

	if !hasArg(cmd.Args, "--no-auth") {
		t.Fatalf("argv missing --no-auth: %#v", cmd.Args)
	}
	if joined := strings.Join(cmd.Args, "\x00"); strings.Contains(joined, token) {
		t.Fatalf("token leaked into argv: %#v", cmd.Args)
	}
	if hasArg(cmd.Args, "--auth-token") || hasArg(cmd.Args, "--auth-token-file") {
		t.Fatalf("argv contains auth flags with no-auth: %#v", cmd.Args)
	}
	if cmd.Env != nil {
		t.Fatalf("command env = %#v, want nil", cmd.Env)
	}
}

func TestHostDaemonCommandPassesUnsafeNoAuth(t *testing.T) {
	cmd := hostDaemonCommand(context.Background(), "/usr/local/bin/fcp", 19285, 19286, true, true, "", "")

	if !hasArg(cmd.Args, "--unsafe-no-auth") {
		t.Fatalf("argv missing --unsafe-no-auth: %#v", cmd.Args)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func hasArgValue(args []string, flag, value string) bool {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}
