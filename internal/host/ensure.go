package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

func Ensure(ctx context.Context, hostIP net.IP, controlPort, dataPort uint16, noAuth, unsafeNoAuth bool, authTokenFile string) error {
	addr := net.TCPAddr{IP: hostIP, Port: int(controlPort)}
	log.Info("ensuring host daemon", "addr", addr.String(), "controlPort", controlPort, "dataPort", dataPort)
	if ping(addr) {
		log.Info("host daemon already running", "port", controlPort)
		return nil
	}

	spawnTokenFile := ""
	if !noAuth {
		if authTokenFile != "" {
			spawnTokenFile = authTokenFile
		} else if envTokenFile := strings.TrimSpace(os.Getenv(auth.EnvAuthTokenFile)); envTokenFile != "" {
			spawnTokenFile = envTokenFile
		} else {
			path, err := auth.TokenFilePath()
			if err != nil {
				return err
			}
			if _, err := auth.EnsureToken(path); err != nil {
				return err
			}
			spawnTokenFile = path
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logPath, _ := log.DefaultDaemonLogPath()
	cmd := hostDaemonCommand(ctx, exe, controlPort, dataPort, noAuth, unsafeNoAuth, spawnTokenFile, logPath)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Error("failed to start host daemon process", "err", err)
		return err
	}
	_ = writePIDFile(cmd.Process.Pid)
	log.Info("host daemon process spawned", "pid", cmd.Process.Pid)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ping(addr) {
			log.Info("host daemon started", "port", controlPort, "pid", cmd.Process.Pid)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("host daemon did not become ready within 5s")
}

func hostDaemonCommand(ctx context.Context, exe string, controlPort, dataPort uint16, noAuth, unsafeNoAuth bool, authTokenFile, logPath string) *exec.Cmd {
	args := []string{"host-daemon", "--control-port", fmt.Sprint(controlPort), "--data-port", fmt.Sprint(dataPort)}
	if noAuth {
		args = append(args, "--no-auth")
		if unsafeNoAuth {
			args = append(args, "--unsafe-no-auth")
		}
	} else if authTokenFile != "" {
		args = append(args, "--auth-token-file", authTokenFile)
	}
	if logPath != "" {
		args = append(args, "--log-file", logPath)
	}

	cmd := exec.CommandContext(ctx, exe, args...) //nolint:gosec // executable is current binary and args are constructed without a shell.
	return cmd
}

func Stop(hostIP net.IP, controlPort uint16, token string) error {
	addr := net.TCPAddr{IP: hostIP, Port: int(controlPort)}
	log.Info("stopping host daemon", "addr", addr.String())
	conn, err := control.DialTCP(addr, 3*time.Second)
	if err != nil {
		log.Warn("host daemon is not running", "addr", addr.String(), "err", err)
		return fmt.Errorf("host daemon is not running on port %d", controlPort)
	}
	defer conn.Close()
	if err := conn.Send(protocol.Shutdown{AuthToken: token}); err != nil {
		log.Error("failed to send shutdown command", "err", err)
		return err
	}
	msg, err := conn.Recv()
	if err != nil {
		return err
	}
	ack, ok := msg.(protocol.ShutdownAck)
	if !ok {
		return fmt.Errorf("unexpected shutdown response %T", msg)
	}
	if !ack.Success {
		if ack.Error != "" {
			return fmt.Errorf("shutdown rejected: %s", ack.Error)
		}
		return fmt.Errorf("shutdown rejected")
	}
	_ = removePIDFile()
	log.Info("host daemon stop command sent")
	return nil
}

func ping(addr net.TCPAddr) bool {
	log.Debug("pinging host daemon", "addr", addr.String())
	conn, err := control.DialTCP(addr, time.Second)
	if err != nil {
		log.Debug("ping failed, daemon not reachable", "addr", addr.String(), "err", err)
		return false
	}
	defer conn.Close()
	if err := conn.Send(protocol.Ping{}); err != nil {
		return false
	}
	msg, err := conn.Recv()
	if err != nil {
		return false
	}
	_, ok := msg.(protocol.Pong)
	return ok
}

func writePIDFile(pid int) error {
	path, err := pidFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprint(pid)), 0o600) //nolint:gosec // pid file is intentionally owner-only.
}

func removePIDFile() error {
	path, err := pidFilePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func pidFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "fcp", "daemon.pid"), nil
}
