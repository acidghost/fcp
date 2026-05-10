package cli

import (
	"os"

	"github.com/acidghost/fcp/internal/log"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show daemon log output",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return log.Replay(os.Stdout, follow)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log output (tail)")

	return cmd
}
