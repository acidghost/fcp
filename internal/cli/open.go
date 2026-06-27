package cli

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
	"github.com/spf13/cobra"
)

func newOpenCmd() *cobra.Command {
	var (
		controlPort   uint
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "open URL",
		Short: "Open URL on host via daemon",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			log.Info("open command invoked", "url", args[0], "controlPort", cp)
			return runOpen(args[0], cp, noAuth, authTokenFile)
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func runOpen(rawURL string, controlPort uint16, noAuth bool, authTokenFile string) error {
	log.Debug("runOpen", "url", rawURL, "controlPort", controlPort)
	if err := protocol.ValidateOpenURL(rawURL); err != nil {
		log.Warn("invalid open URL", "url", rawURL, "err", err)
		return err
	}
	token, err := resolveCommandToken(noAuth, authTokenFile)
	if err != nil {
		return err
	}
	addr := net.TCPAddr{IP: config.ResolveCLIHost(""), Port: int(controlPort)}
	conn, err := control.DialTCP(addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("could not connect to host daemon at %s: %w", addr.String(), err)
	}
	defer conn.Close()
	if err := conn.Send(protocol.OpenURL{URL: rawURL, AuthToken: token}); err != nil {
		return err
	}
	msg, err := conn.Recv()
	if err != nil {
		return err
	}
	ack, ok := msg.(protocol.OpenURLAck)
	if !ok || !ack.Success {
		log.Error("host daemon failed to open URL")
		if ok && ack.Error != "" {
			return fmt.Errorf("host daemon failed to open URL: %s", ack.Error)
		}
		return errors.New("host daemon failed to open URL")
	}
	log.Info("URL opened successfully")
	return nil
}
