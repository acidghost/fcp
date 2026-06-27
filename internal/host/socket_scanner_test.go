package host

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acidghost/fcp/internal/config"
)

func TestSocketScannerDetectsAndRemovesSocket(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "nested", "test.sock")
	if err := ensureDir(filepath.Dir(sockPath)); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix sockets unavailable in this sandbox: %v", err)
	}
	defer ln.Close()

	scanner := NewSocketScanner([]string{filepath.Join(tmp, "**", "*.sock")}, "/run/host-sockets", 4)
	found, removed := scanner.Scan()
	if len(found) != 1 || len(removed) != 0 {
		t.Fatalf("found=%d removed=%d, want 1/0", len(found), len(removed))
	}
	wantContainerPath := filepath.Join("/run/host-sockets", "test.sock-"+shortPathHash(sockPath))
	if found[0].HostPath != sockPath || found[0].ContainerPath != wantContainerPath {
		t.Fatalf("unexpected socket info: %#v", found[0])
	}
	_ = ln.Close()
	found, removed = scanner.Scan()
	if len(found) != 0 || len(removed) != 1 {
		t.Fatalf("found=%d removed=%d, want 0/1", len(found), len(removed))
	}
}

func TestSocketScannerExplicitRuleUsesConfiguredMirrorPath(t *testing.T) {
	tmp := t.TempDir()
	sockPath := listenUnixSocket(t, filepath.Join(tmp, "host.sock"))
	containerPath := filepath.Join(tmp, "container", "mirror.sock")
	scanner := NewSocketScannerFromConfig(config.SocketForwardingConfig{
		Rules: []config.SocketForwardRule{{HostPath: sockPath, ContainerPath: containerPath}},
	})

	found, removed := scanner.Scan()
	if len(found) != 1 || len(removed) != 0 {
		t.Fatalf("found=%d removed=%d, want 1/0", len(found), len(removed))
	}
	if found[0].HostPath != sockPath || found[0].ContainerPath != containerPath {
		t.Fatalf("unexpected socket info: %#v", found[0])
	}
}

func TestSocketScannerDerivedMirrorPathsAvoidBasenameCollisions(t *testing.T) {
	tmp := t.TempDir()
	first := listenUnixSocket(t, filepath.Join(tmp, "a", "api.sock"))
	second := listenUnixSocket(t, filepath.Join(tmp, "b", "api.sock"))
	scanner := NewSocketScannerFromConfig(config.SocketForwardingConfig{
		WatchPaths:               []string{filepath.Join(tmp, "**", "*.sock")},
		ContainerPathPrefix:      "/run/fcp",
		MaxSocketForwards:        4,
		AllowRecursiveSocketGlob: true,
	})

	found, removed := scanner.Scan()
	if len(found) != 2 || len(removed) != 0 {
		t.Fatalf("found=%d removed=%d, want 2/0", len(found), len(removed))
	}
	if found[0].ContainerPath == found[1].ContainerPath {
		t.Fatalf("container paths collided: %#v", found)
	}
	for _, info := range found {
		if !strings.HasPrefix(filepath.Base(info.ContainerPath), "api.sock-") {
			t.Fatalf("derived path lacks stable basename hash: %#v", info)
		}
	}
	if found[0].HostPath != first || found[1].HostPath != second {
		t.Fatalf("socket scan order not deterministic: %#v", found)
	}
}

func TestSocketForwardingConfigRequiresAcknowledgements(t *testing.T) {
	sensitive := config.SocketForwardingConfig{
		Enabled: true,
		Rules:   []config.SocketForwardRule{{HostPath: "/var/run/docker.sock", ContainerPath: "/run/fcp/docker.sock"}},
	}
	if err := ValidateSocketForwardingConfig(sensitive); err == nil || !strings.Contains(err.Error(), "--allow-sensitive-sockets") {
		t.Fatalf("sensitive validation err = %v, want allow-sensitive error", err)
	}
	sensitive.AllowSensitiveSockets = true
	if err := ValidateSocketForwardingConfig(sensitive); err != nil {
		t.Fatalf("sensitive validation with acknowledgement: %v", err)
	}

	recursive := config.SocketForwardingConfig{Enabled: true, WatchPaths: []string{"/run/**/*.sock"}}
	if err := ValidateSocketForwardingConfig(recursive); err == nil || !strings.Contains(err.Error(), "--allow-recursive-socket-globs") {
		t.Fatalf("recursive validation err = %v, want allow-recursive error", err)
	}
	recursive.AllowRecursiveSocketGlob = true
	if err := ValidateSocketForwardingConfig(recursive); err != nil {
		t.Fatalf("recursive validation with acknowledgement: %v", err)
	}
}

func TestSocketScannerSkipsSensitiveGlobMatchesWithoutAcknowledgement(t *testing.T) {
	tmp := t.TempDir()
	_ = listenUnixSocket(t, filepath.Join(tmp, "docker.sock"))
	scanner := NewSocketScannerFromConfig(config.SocketForwardingConfig{
		WatchPaths:          []string{filepath.Join(tmp, "*.sock")},
		ContainerPathPrefix: "/run/fcp",
	})

	found, removed := scanner.Scan()
	if len(found) != 0 || len(removed) != 0 {
		t.Fatalf("found=%d removed=%d, want 0/0", len(found), len(removed))
	}
}

func TestIsSensitiveHostSocket(t *testing.T) {
	sensitive := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/podman/podman.sock",
		"/Users/me/.colima/default/docker.sock",
	}
	for _, path := range sensitive {
		if !isSensitiveHostSocket(path) {
			t.Fatalf("isSensitiveHostSocket(%q) = false, want true", path)
		}
	}
	if isSensitiveHostSocket("/tmp/project/app.sock") {
		t.Fatal("ordinary project socket classified as sensitive")
	}
}

func listenUnixSocket(t *testing.T, path string) string {
	t.Helper()
	if err := ensureDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable in this sandbox: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return path
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0o700)
}
