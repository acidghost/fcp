// Package log provides a centralized logger for fcp, wrapping
// charm.land/log/v2. Daemon commands can redirect output
// to a file; the "logs" CLI sub-command replays those log files.
package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"charm.land/log/v2"
)

var (
	global   *log.Logger
	globalMu sync.Mutex
)

func init() {
	global = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Level:           log.InfoLevel,
	})
}

// SetupFile configures the global logger to write to path.
// If path is empty the logger writes to stderr (foreground mode).
func SetupFile(path string) error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if path == "" {
		global.SetOutput(os.Stderr)
		log.SetOutput(os.Stderr)
		log.SetLevel(log.InfoLevel)
		global.Info("log output set to stderr (foreground mode)")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // log file path is derived from user home config dir
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	global.SetOutput(f)
	global.SetLevel(log.DebugLevel)
	log.SetOutput(f)
	log.SetLevel(log.DebugLevel)
	global.Info("log output redirected to file", "path", path)
	return nil
}

// L returns the global logger.
func L() *log.Logger {
	globalMu.Lock()
	defer globalMu.Unlock()
	return global
}

// SetLevel changes the global log level.
func SetLevel(level log.Level) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global.SetLevel(level)
}

// Debug logs with debug level.
func Debug(msg string, kvs ...any) {
	L().Debug(msg, kvs...)
}

// Info logs with info level.
func Info(msg string, kvs ...any) {
	L().Info(msg, kvs...)
}

// Warn logs with warn level.
func Warn(msg string, kvs ...any) {
	L().Warn(msg, kvs...)
}

// Error logs with error level.
func Error(msg string, kvs ...any) {
	L().Error(msg, kvs...)
}

// Debugf logs formatted debug.
func Debugf(format string, args ...any) {
	L().Debug(fmt.Sprintf(format, args...))
}

// Infof logs formatted info.
func Infof(format string, args ...any) {
	L().Info(fmt.Sprintf(format, args...))
}

// Warnf logs formatted warn.
func Warnf(format string, args ...any) {
	L().Warn(fmt.Sprintf(format, args...))
}

// Errorf logs formatted error.
func Errorf(format string, args ...any) {
	L().Error(fmt.Sprintf(format, args...))
}

// DefaultDaemonLogPath returns the default path for daemon log files,
// or an error if the config directory cannot be resolved.
func DefaultDaemonLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "fcp", "daemon.log"), nil
}

// Replay reads the daemon log file and writes it to w.
// If follow is true, it tails the file for new entries.
func Replay(w io.Writer, follow bool) error {
	path, err := DefaultDaemonLogPath()
	if err != nil {
		return fmt.Errorf("resolve log path: %w", err)
	}
	global.Info("replaying daemon log", "path", path, "follow", follow)

	f, err := os.Open(path) //nolint:gosec // log file path is derived from user home config dir
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(w, "No daemon log file found.")
			return nil
		}
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	// Write existing content.
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("read log file: %w", err)
	}

	if !follow {
		return nil
	}

	// Tail: poll for new data until interrupted.
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if err != nil {
			return fmt.Errorf("read log file: %w", err)
		}
	}
}
