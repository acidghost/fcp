package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/host"
	"github.com/acidghost/fcp/internal/log"
	"github.com/spf13/cobra"
)

func newEnsureCmd() *cobra.Command {
	var (
		controlPort   uint
		dataPort      uint
		hostFlag      string
		authToken     string
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "ensure",
		Short: "Start host daemon if needed",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			dp, err := flagPort(dataPort)
			if err != nil {
				return err
			}
			if err := host.Ensure(ctx, config.ResolveCLIHost(hostFlag), cp, dp, noAuth, authToken, authTokenFile); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().UintVar(&dataPort, "data-port", uint(config.DefaultDataPort), "data port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func newStopCmd() *cobra.Command {
	var (
		controlPort   uint
		hostFlag      string
		authToken     string
		authTokenFile string
	)

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop host daemon",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return execStop(hostFlag, controlPort, authToken, authTokenFile)
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")

	return cmd
}

func newRestartCmd() *cobra.Command {
	var (
		controlPort   uint
		dataPort      uint
		hostFlag      string
		authToken     string
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Stop then ensure host daemon",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := execStop(hostFlag, controlPort, authToken, authTokenFile); err != nil {
				log.Warn("stop failed or daemon was not running; continuing with ensure")
			}
			time.Sleep(500 * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			dp, err := flagPort(dataPort)
			if err != nil {
				return err
			}
			if err := host.Ensure(ctx, config.ResolveCLIHost(hostFlag), cp, dp, noAuth, authToken, authTokenFile); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().UintVar(&dataPort, "data-port", uint(config.DefaultDataPort), "data port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func execStop(hostFlag string, controlPort uint, authToken, authTokenFile string) error {
	log.Info("stop command invoked", "controlPort", controlPort)
	cp, err := flagPort(controlPort)
	if err != nil {
		return err
	}
	if err := host.Stop(config.ResolveCLIHost(hostFlag), cp, auth.ResolveCLIToken(authToken, authTokenFile)); err != nil {
		log.Error("stop command failed", "err", err)
		return err
	}
	fmt.Println("Host daemon stopped.")
	return nil
}
