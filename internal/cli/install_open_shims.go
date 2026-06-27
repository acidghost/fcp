package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var defaultOpenShimNames = []string{"fcp-open", "xdg-open", "open", "sensible-browser"}

func newInstallOpenShimsCmd() *cobra.Command {
	var (
		dirFlag string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "install-open-shims",
		Short: "Install xdg-open/open shims that forward URLs to the host",
		Long: `Install symlinks named fcp-open, xdg-open, open, and sensible-browser into a bin directory.
When invoked, these names ask the fcp host daemon to open http(s) URLs on the host.
Put the install directory before system directories in PATH to make xdg-open/open transparent inside a container.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := expandHome(dirFlag)
			if err != nil {
				return err
			}
			target, err := currentExecutablePath()
			if err != nil {
				return err
			}
			if err := installOpenShims(dir, target, defaultOpenShimNames, force); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "installed open shims in %s -> %s\n", dir, target)
			if !pathContainsDir(os.Getenv("PATH"), dir) {
				fmt.Fprintf(out, "add this to your shell profile inside the container:\n  export PATH=%q:$PATH\n", dir)
			}
			fmt.Fprintln(out, "optional: export BROWSER=fcp-open")
			return nil
		},
	}

	cmd.Flags().StringVar(&dirFlag, "dir", "~/.local/bin", "directory where shims will be installed")
	cmd.Flags().BoolVar(&force, "force", false, "replace existing shim paths")
	return cmd
}

func currentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

func installOpenShims(dir, target string, names []string, force bool) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("open shims are only supported on Unix-like systems")
	}
	if dir == "" {
		return fmt.Errorf("install directory cannot be empty")
	}
	if target == "" {
		return fmt.Errorf("shim target cannot be empty")
	}
	//nolint:gosec // bin directories must be traversable by normal users; files are symlinks to an existing executable.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create shim directory %s: %w", dir, err)
	}
	for _, name := range names {
		if strings.ContainsRune(name, os.PathSeparator) || name == "" || name == "." || name == ".." {
			return fmt.Errorf("invalid shim name %q", name)
		}
		path := filepath.Join(dir, name)
		if err := installOneShim(path, target, force); err != nil {
			return err
		}
	}
	return nil
}

func installOneShim(path, target string, force bool) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			existingTarget, readErr := os.Readlink(path)
			if readErr != nil {
				return fmt.Errorf("read existing shim %s: %w", path, readErr)
			}
			if sameShimTarget(path, existingTarget, target) {
				return nil
			}
		}
		if !force {
			return fmt.Errorf("%s already exists; use --force to replace it", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("replace existing shim %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect shim path %s: %w", path, err)
	}
	if err := os.Symlink(target, path); err != nil {
		return fmt.Errorf("create shim %s -> %s: %w", path, target, err)
	}
	return nil
}

func sameShimTarget(linkPath, existingTarget, target string) bool {
	if existingTarget == target {
		return true
	}
	if !filepath.IsAbs(existingTarget) {
		existingTarget = filepath.Join(filepath.Dir(linkPath), existingTarget)
	}
	existingAbs, existingErr := filepath.Abs(existingTarget)
	targetAbs, targetErr := filepath.Abs(target)
	if existingErr != nil || targetErr != nil {
		return false
	}
	if existingResolved, err := filepath.EvalSymlinks(existingAbs); err == nil {
		existingAbs = existingResolved
	}
	if targetResolved, err := filepath.EvalSymlinks(targetAbs); err == nil {
		targetAbs = targetResolved
	}
	return existingAbs == targetAbs
}

func expandHome(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return filepath.Clean(path), nil
	}
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return "", fmt.Errorf("cannot expand %q; only ~ and ~/... are supported", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

func pathContainsDir(pathValue, dir string) bool {
	if pathValue == "" || dir == "" {
		return false
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	for _, entry := range filepath.SplitList(pathValue) {
		if entry == "" {
			continue
		}
		entryAbs, err := filepath.Abs(entry)
		if err != nil {
			continue
		}
		if entryAbs == dirAbs {
			return true
		}
	}
	return false
}
