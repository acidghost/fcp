package cli

import (
	"errors"
	"fmt"
	"net"

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
		authToken          string
		authTokenFile      string
		noAuth             bool
		socketWatchPaths   string
		socketPrefix       string
		socketScanMS       uint64
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
				resolvedToken, err = auth.ResolveToken(authToken, authTokenFile, defaultPath)
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
				SocketForwarding: config.SocketForwardingConfig{
					Enabled:             !noSocketForwarding && socketWatchPaths != "",
					WatchPaths:          splitComma(socketWatchPaths),
					ContainerPathPrefix: socketPrefix,
					ScanIntervalMillis:  socketScanMS,
					MaxSocketForwards:   config.DefaultMaxSocketForwards,
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
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")
	cmd.Flags().StringVar(&socketWatchPaths, "socket-watch-paths", "", "comma-separated socket globs")
	cmd.Flags().StringVar(&socketPrefix, "socket-container-path-prefix", "", "socket container path prefix")
	cmd.Flags().Uint64Var(&socketScanMS, "socket-scan-interval-ms", config.DefaultSocketScanMillis, "socket scan interval")
	cmd.Flags().BoolVar(&noSocketForwarding, "no-socket-forwarding", false, "disable socket forwarding")
	cmd.Flags().StringVar(&logFile, "log-file", "", "log file")

	return cmd
}
