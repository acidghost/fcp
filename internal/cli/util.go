package cli

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/log"
)

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sig)
	}()
	return ctx, cancel
}

func setupLog(path string) {
	if err := log.SetupFile(path); err != nil {
		// Fall back to stderr — don't fail the daemon start just because
		// the log path is bad.
		log.Error("failed to set up log file", "path", path, "err", err)
	}
}

func flagPort(value uint) (uint16, error) {
	return config.ParsePort(strconv.FormatUint(uint64(value), 10))
}

func splitComma(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func resolveCommandToken(noAuth bool, authTokenFile string) (string, error) {
	if noAuth {
		return "", nil
	}
	return auth.ResolveClientToken(authTokenFile)
}
