package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallOpenShims(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fcp")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := installOpenShims(dir, target, []string{"fcp-open", "xdg-open"}, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fcp-open", "xdg-open"} {
		path := filepath.Join(dir, name)
		got, err := os.Readlink(path)
		if err != nil {
			t.Fatalf("%s was not installed as a symlink: %v", name, err)
		}
		if got != target {
			t.Fatalf("%s points to %q, want %q", name, got, target)
		}
	}

	if err := installOpenShims(dir, target, []string{"fcp-open", "xdg-open"}, false); err != nil {
		t.Fatalf("reinstalling identical shims should be idempotent: %v", err)
	}
}

func TestInstallOpenShimsRefusesConflictUnlessForced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fcp")
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "xdg-open")); err != nil {
		t.Fatal(err)
	}

	if err := installOpenShims(dir, target, []string{"xdg-open"}, false); err == nil {
		t.Fatal("expected conflict without --force")
	}
	if err := installOpenShims(dir, target, []string{"xdg-open"}, true); err != nil {
		t.Fatalf("expected --force to replace conflict: %v", err)
	}
	got, err := os.Readlink(filepath.Join(dir, "xdg-open"))
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("forced shim points to %q, want %q", got, target)
	}
}

func TestOpenShimNames(t *testing.T) {
	for _, name := range []string{"fcp-open", "xdg-open", "open", "sensible-browser"} {
		if !isOpenShimName(name) {
			t.Fatalf("%q should be an open shim name", name)
		}
	}
	if isOpenShimName("fcp") {
		t.Fatal("fcp should not be an open shim name")
	}
}
