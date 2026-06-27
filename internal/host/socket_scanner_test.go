package host

import (
	"net"
	"os"
	"path/filepath"
	"testing"
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
	if found[0].HostPath != sockPath || found[0].ContainerPath != "/run/host-sockets/test.sock" {
		t.Fatalf("unexpected socket info: %#v", found[0])
	}
	_ = ln.Close()
	found, removed = scanner.Scan()
	if len(found) != 0 || len(removed) != 1 {
		t.Fatalf("found=%d removed=%d, want 0/1", len(found), len(removed))
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

func ensureDir(path string) error {
	return os.MkdirAll(path, 0o700)
}
