package cli

import (
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/container"
	"github.com/acidghost/fcp/internal/log"
	"github.com/spf13/cobra"
)

func newContainerDaemonCmd() *cobra.Command {
	var (
		hostAddr      string
		scanInterval  uint64
		excludePorts  string
		authTokenFile string
		noAuth        bool
		logFile       string
	)

	cmd := &cobra.Command{
		Use:   "container-daemon",
		Short: "Start container-side scanner/proxy daemon",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLog(logFile)
			log.Info("container-daemon command invoked", "hostAddr", hostAddr, "scanInterval", scanInterval, "excludePorts", excludePorts)
			cfg, err := config.FromEnv()
			if err != nil {
				return err
			}
			if hostAddr != "" {
				cfg.HostAddr = hostAddr
			}
			cfg.ScanIntervalMillis = scanInterval
			ports, err := config.ParsePortList(excludePorts)
			if err != nil {
				return err
			}
			cfg.ExcludePorts = ports
			token, err := resolveCommandToken(noAuth, authTokenFile)
			if err != nil {
				return err
			}
			log.Debug("container token resolved", "hasToken", token != "")
			ctx, stop := signalContext()
			defer stop()
			if err := container.Run(ctx, cfg, token); err != nil {
				log.Error("container daemon exited with error", "err", err)
				return err
			}
			log.Info("container daemon exited cleanly")
			return nil
		},
	}

	cmd.Flags().StringVar(&hostAddr, "host-addr", "", "host address")
	cmd.Flags().Uint64Var(&scanInterval, "scan-interval", config.DefaultScanIntervalMillis, "scan interval ms")
	cmd.Flags().StringVar(&excludePorts, "exclude-ports", "", "comma-separated exclude ports")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")
	cmd.Flags().StringVar(&logFile, "log-file", "", "log file")

	return cmd
}
