package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveMirrorSocketKeepsExistingParentDirectory(t *testing.T) {
	root := shortTempDir(t)
	parent := filepath.Join(root, "existing")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	mirror := createMirrorOrSkip(t, filepath.Join(parent, "mirror.sock"))

	RemoveMirrorSocket(mirror)

	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("existing parent directory was removed: %v", err)
	}
	if _, err := os.Stat(mirror.ContainerPath); !os.IsNotExist(err) {
		t.Fatalf("mirror socket still exists or stat failed: %v", err)
	}
}

func TestRemoveMirrorSocketRemovesOnlyCreatedEmptyDirectories(t *testing.T) {
	root := shortTempDir(t)
	parent := filepath.Join(root, "created", "nested")
	mirror := createMirrorOrSkip(t, filepath.Join(parent, "mirror.sock"))

	RemoveMirrorSocket(mirror)

	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("created nested parent still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "created")); !os.IsNotExist(err) {
		t.Fatalf("created top parent still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("temp root should remain: %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "fcp-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func createMirrorOrSkip(t *testing.T, path string) *MirrorSocket {
	t.Helper()
	mirror, err := CreateMirrorSocket("sock-test", path)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("unix sockets unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	return mirror
}
