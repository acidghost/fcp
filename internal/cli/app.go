package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

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
	if len(os.Args) > 0 && isOpenShimName(filepath.Base(os.Args[0])) {
		return executeOpenShim(filepath.Base(os.Args[0]), os.Args[1:])
	}

	rootCmd := newRootCmd(build)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func isOpenShimName(name string) bool {
	return slices.Contains(defaultOpenShimNames, name)
}

func executeOpenShim(name string, args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintf(os.Stdout, "usage: %s <URL>\n", name)
		return 0
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s <URL>\n", name)
		return 1
	}
	cfg, err := config.FromEnv()
	if err != nil {
		log.Warn("failed to parse env config", "err", err)
	}
	if err := runOpen(args[0], cfg.ControlPort, false, "", ""); err != nil {
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
		newInstallOpenShimsCmd(),
		newLogsCmd(),
	)

	return rootCmd
}
