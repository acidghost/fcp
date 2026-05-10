package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/log"
	"github.com/spf13/cobra"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Execute is the main entry point for the CLI.
func Execute(build BuildInfo) int {
	log.Debug("fcp CLI starting", "version", build.Version, "commit", build.Commit)
	// Handle fcp-open binary symlink
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "fcp-open" {
		if len(os.Args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fcp-open <URL>")
			return 1
		}
		cfg, err := config.FromEnv()
		if err != nil {
			log.Warn("failed to parse env config", "err", err)
		}
		if err := runOpen(os.Args[1], cfg.ControlPort, "", ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	rootCmd := newRootCmd(build)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func newRootCmd(build BuildInfo) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "fcp",
		Short:         "forward container ports",
		Version:       fmt.Sprintf("%s (commit: %s, date: %s)", build.Version, build.Commit, build.Date),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.SetVersionTemplate(fmt.Sprintf("Version: %s\nCommit:  %s\nDate:    %s\n", build.Version, build.Commit, build.Date))

	rootCmd.AddCommand(
		newHostDaemonCmd(),
		newContainerDaemonCmd(),
		newEnsureCmd(),
		newStopCmd(),
		newRestartCmd(),
		newStatusCmd(),
		newForwardCmd(),
		newUnforwardCmd(),
		newOpenCmd(),
		newLogsCmd(),
	)

	return rootCmd
}
