package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
	"github.com/spf13/cobra"
)

func newForwardCmd() *cobra.Command {
	var (
		controlPort   uint
		hostFlag      string
		authToken     string
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "forward PORT",
		Short: "Manually request a forward",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			port, err := config.ParsePort(args[0])
			if err != nil {
				return err
			}
			log.Info("forward command invoked", "port", port, "controlPort", controlPort)
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			addr := net.TCPAddr{IP: config.ResolveCLIHost(hostFlag), Port: int(cp)}
			conn, err := control.DialTCP(addr, 3*time.Second)
			if err != nil {
				return fmt.Errorf("could not connect to host daemon at %s: %w", addr.String(), err)
			}
			defer conn.Close()
			token, err := resolveCommandToken(noAuth, authToken, authTokenFile)
			if err != nil {
				return err
			}
			if err := conn.Send(protocol.Register{ContainerID: "cli-manual", Hostname: "cli", AuthToken: token}); err != nil {
				return err
			}
			msg, err := conn.Recv()
			if err != nil {
				return err
			}
			if ack, ok := msg.(protocol.RegisterAck); !ok || !ack.Success {
				return errors.New("host daemon rejected registration")
			}
			if err := conn.Send(protocol.Forward{Port: port, Protocol: protocol.ProtocolTCP}); err != nil {
				return err
			}
			msg, err = conn.Recv()
			if err != nil {
				return err
			}
			ack, ok := msg.(protocol.ForwardAck)
			if !ok || !ack.Success {
				log.Error("host daemon failed to forward port", "port", port)
				return fmt.Errorf("host daemon failed to forward port %d", port)
			}
			log.Info("port forwarded successfully", "containerPort", port, "hostPort", ack.HostPort)
			fmt.Printf("Forwarding port %d → host port %d\nPress Ctrl-C to stop forwarding.\n", port, ack.HostPort)
			return holdManualForward(conn, port)
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func newUnforwardCmd() *cobra.Command {
	var (
		controlPort   uint
		hostFlag      string
		authToken     string
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "unforward PORT",
		Short: "Remove a forward",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			port, err := config.ParsePort(args[0])
			if err != nil {
				return err
			}
			log.Info("unforward command invoked", "port", port, "controlPort", controlPort)
			cp, err := flagPort(controlPort)
			if err != nil {
				return err
			}
			addr := net.TCPAddr{IP: config.ResolveCLIHost(hostFlag), Port: int(cp)}
			conn, err := control.DialTCP(addr, 3*time.Second)
			if err != nil {
				return fmt.Errorf("could not connect to host daemon at %s: %w", addr.String(), err)
			}
			defer conn.Close()
			token, err := resolveCommandToken(noAuth, authToken, authTokenFile)
			if err != nil {
				return err
			}
			if err := conn.Send(protocol.Unforward{Port: port, AuthToken: token}); err != nil {
				return err
			}
			msg, err := conn.Recv()
			if err != nil {
				return err
			}
			ack, ok := msg.(protocol.UnforwardAck)
			if !ok {
				return fmt.Errorf("unexpected unforward response %T", msg)
			}
			if !ack.Success {
				if ack.Error != "" {
					return fmt.Errorf("unforward rejected: %s", ack.Error)
				}
				fmt.Printf("No active forward found for port %d.\n", port)
				return nil
			}
			log.Info("unforwarded port", "port", port)
			fmt.Printf("Unforwarded port %d.\n", port)
			return nil
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func holdManualForward(conn *control.Connection, port uint16) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	msgCh := make(chan protocol.Message, 1)
	errCh := make(chan error, 1)
	readNext := func() {
		go func() {
			msg, err := conn.Recv()
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}()
	}
	readNext()
	for {
		select {
		case <-sig:
			_ = conn.Send(protocol.Unforward{Port: port})
			log.Info("manual forward stopped by signal", "port", port)
			fmt.Printf("Stopped forwarding port %d.\n", port)
			return nil
		case msg := <-msgCh:
			switch m := msg.(type) {
			case protocol.Ping:
				_ = conn.Send(protocol.Pong{})
			case protocol.ConnectRequest:
				_ = conn.Send(protocol.ConnectFailed{ConnID: m.ConnID, Error: "manual forward does not support proxying"})
			}
			readNext()
		case <-errCh:
			return errors.New("host daemon rejected registration")
		}
	}
}
