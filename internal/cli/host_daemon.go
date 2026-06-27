package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/host"
	"github.com/acidghost/fcp/internal/log"
	"github.com/spf13/cobra"
)

func newHostDaemonCmd() *cobra.Command {
	var (
		bindAddr           string
		noDockerDetect     bool
		controlPort        uint
		dataPort           uint
		exitOnIdle         bool
		browserCmd         string
		authTokenFile      string
		noAuth             bool
		unsafeNoAuth       bool
		socketWatchPaths   string
		socketForwards     []string
		socketPrefix       string
		socketScanMS       uint64
		socketScanBudgetMS uint64
		allowSensitive     bool
		allowRecursive     bool
		noSocketForwarding bool
		logFile            string
	)

	cmd := &cobra.Command{
		Use:   "host-daemon",
		Short: "Start host-side control/data daemons",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLog(logFile)
			log.Info("host-daemon command invoked", "bindAddr", bindAddr, "controlPort", controlPort, "dataPort", dataPort, "noAuth", noAuth, "exitOnIdle", exitOnIdle)

			resolvedToken := ""
			if !noAuth {
				defaultPath, err := auth.TokenFilePath()
				if err != nil {
					return err
				}
				resolvedToken, err = auth.ResolveToken(authTokenFile, defaultPath)
				if errors.Is(err, auth.ErrNoTokenSource) {
					resolvedToken, err = auth.EnsureToken(defaultPath)
				}
				if err != nil {
					return err
				}
			}
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			dp, err := flagPort(dataPort)
			if err != nil {
				return err
			}
			var ip net.IP
			if bindAddr != "" {
				ip = net.ParseIP(bindAddr)
				if ip == nil {
					return fmt.Errorf("invalid --bind-addr %q", bindAddr)
				}
			}
			socketRules, err := parseSocketForwardRules(socketForwards)
			if err != nil {
				return err
			}

			ctx, stop := signalContext()
			defer stop()
			cfg := host.Config{
				ControlPort:    cp,
				DataPort:       dp,
				BindAddr:       ip,
				NoDockerDetect: noDockerDetect,
				ExitOnIdle:     exitOnIdle,
				BrowserCommand: browserCmd,
				AuthToken:      resolvedToken,
				NoAuth:         noAuth,
				UnsafeNoAuth:   unsafeNoAuth,
				SocketForwarding: config.SocketForwardingConfig{
					Enabled:                  !noSocketForwarding && (socketWatchPaths != "" || len(socketRules) > 0),
					Rules:                    socketRules,
					WatchPaths:               splitComma(socketWatchPaths),
					ContainerPathPrefix:      socketPrefix,
					ScanIntervalMillis:       socketScanMS,
					ScanBudgetMillis:         socketScanBudgetMS,
					MaxSocketForwards:        config.DefaultMaxSocketForwards,
					AllowSensitiveSockets:    allowSensitive,
					AllowRecursiveSocketGlob: allowRecursive,
				},
			}
			if err := host.Run(ctx, cfg); err != nil {
				log.Error("host daemon exited with error", "err", err)
				return err
			}
			log.Info("host daemon exited cleanly")
			return nil
		},
	}

	cmd.Flags().StringVar(&bindAddr, "bind-addr", "", "bind address")
	cmd.Flags().BoolVar(&noDockerDetect, "no-docker-detect", false, "disable docker detection")
	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().UintVar(&dataPort, "data-port", uint(config.DefaultDataPort), "data port")
	cmd.Flags().BoolVar(&exitOnIdle, "exit-on-idle", false, "exit when idle")
	cmd.Flags().StringVar(&browserCmd, "browser-cmd", "", "browser command")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")
	cmd.Flags().BoolVar(&unsafeNoAuth, "unsafe-no-auth", false, "allow --no-auth on non-loopback bind addresses")
	cmd.Flags().StringArrayVar(&socketForwards, "socket-forward", nil, "explicit socket forward in host_path:container_path form; repeatable")
	cmd.Flags().StringVar(&socketWatchPaths, "socket-watch-paths", "", "comma-separated socket globs")
	cmd.Flags().StringVar(&socketPrefix, "socket-container-path-prefix", "", "socket container path prefix")
	cmd.Flags().Uint64Var(&socketScanMS, "socket-scan-interval-ms", config.DefaultSocketScanMillis, "socket scan interval")
	cmd.Flags().Uint64Var(&socketScanBudgetMS, "socket-scan-budget-ms", config.DefaultSocketScanBudgetMillis, "socket scan traversal budget")
	cmd.Flags().BoolVar(&allowSensitive, "allow-sensitive-sockets", false, "allow forwarding high-risk host sockets such as Docker/runtime sockets")
	cmd.Flags().BoolVar(&allowRecursive, "allow-recursive-socket-globs", false, "allow recursive ** socket glob patterns")
	cmd.Flags().BoolVar(&noSocketForwarding, "no-socket-forwarding", false, "disable socket forwarding")
	cmd.Flags().StringVar(&logFile, "log-file", "", "log file")

	return cmd
}

func parseSocketForwardRules(values []string) ([]config.SocketForwardRule, error) {
	rules := make([]config.SocketForwardRule, 0, len(values))
	for _, value := range values {
		hostPath, containerPath, ok := strings.Cut(value, ":")
		if !ok {
			return nil, fmt.Errorf("invalid --socket-forward %q: expected host_path:container_path", value)
		}
		hostPath = strings.TrimSpace(hostPath)
		containerPath = strings.TrimSpace(containerPath)
		if hostPath == "" || containerPath == "" {
			return nil, fmt.Errorf("invalid --socket-forward %q: host and container paths are required", value)
		}
		rules = append(rules, config.SocketForwardRule{HostPath: hostPath, ContainerPath: containerPath})
	}
	return rules, nil
}
