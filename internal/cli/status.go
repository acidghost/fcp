package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var (
		controlPort   uint
		hostFlag      string
		jsonOut       bool
		authToken     string
		authTokenFile string
		noAuth        bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show active port and socket forwards",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			log.Debug("status command invoked", "controlPort", controlPort)
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
			if err := conn.Send(protocol.ListRequest{AuthToken: token}); err != nil {
				return err
			}
			msg, err := conn.Recv()
			if err != nil {
				return err
			}
			resp, ok := msg.(protocol.ListResponse)
			if !ok {
				log.Error("unexpected response type from daemon", "type", fmt.Sprintf("%T", msg))
				return fmt.Errorf("unexpected response %T", msg)
			}
			if !resp.Success {
				if resp.Error != "" {
					return fmt.Errorf("status rejected: %s", resp.Error)
				}
				return fmt.Errorf("status rejected")
			}
			log.Debug("status response received", "forwards", len(resp.Forwards), "socketForwards", len(resp.SocketForwards))
			if jsonOut {
				data, _ := json.MarshalIndent(resp, "", "  ")
				fmt.Println(string(data))
			} else {
				printStatus(resp)
			}
			return nil
		},
	}

	cmd.Flags().UintVar(&controlPort, "control-port", uint(config.DefaultControlPort), "control port")
	cmd.Flags().StringVar(&hostFlag, "host", "", "host")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "json output")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "auth token")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "auth token file")
	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "disable auth")

	return cmd
}

func printStatus(resp protocol.ListResponse) {
	if len(resp.Forwards) == 0 && len(resp.SocketForwards) == 0 {
		fmt.Println("No active forwards.")
		return
	}
	if len(resp.Forwards) > 0 {
		fmt.Printf("%-20s %5s   %9s  %-12s %s\n", "Container", "Port", "Host Port", "Process", "Since")
		for _, fwd := range resp.Forwards {
			process := "-"
			if fwd.ProcessName != nil && *fwd.ProcessName != "" {
				process = *fwd.ProcessName
			}
			fmt.Printf("%-20s %5d   %9d  %-12s %s\n", fwd.Hostname, fwd.Port, fwd.HostPort, process, formatSince(fwd.Since))
		}
	}
	if len(resp.SocketForwards) > 0 {
		if len(resp.Forwards) > 0 {
			fmt.Println()
		}
		fmt.Printf("%-36s %-40s %s\n", "Socket ID", "Host Path", "Container Path")
		for _, sf := range resp.SocketForwards {
			fmt.Printf("%-36s %-40s %s\n", sf.SocketID, sf.HostPath, sf.ContainerPath)
		}
	}
}

func formatSince(s string) string {
	secs, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return s
	}
	elapsed := time.Since(time.Unix(secs, 0))
	switch {
	case elapsed < time.Minute:
		return fmt.Sprintf("%ds ago", int(elapsed.Seconds()))
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm ago", int(elapsed.Minutes()))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(elapsed.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(elapsed.Hours()/24))
	}
}
