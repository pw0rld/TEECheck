package actions_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func TestResolvePath_AcceptsRelativeInsideRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := actions.ResolvePath(dir, "a.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, "a.txt")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolvePath_AcceptsCurrentDir(t *testing.T) {
	dir := t.TempDir()
	got, err := actions.ResolvePath(dir, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ResolvePath(dir, ".") must return exactly dir (after any OS-level
	// normalization from filepath.Abs), not a prefix of it.
	want, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolvePath_RejectsDotDotEscape(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "../secret")
	if err == nil {
		t.Fatal("expected error for ../secret, got nil")
	}
	if !strings.Contains(err.Error(), "escape") {
		t.Fatalf("expected escape error, got %v", err)
	}
}

func TestResolvePath_RejectsEmbeddedDotDot(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "subdir/../../outside")
	if err == nil {
		t.Fatal("expected error for subdir/../../outside, got nil")
	}
}

func TestResolvePath_RejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestResolvePath_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test uses POSIX semantics")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Join(outside, "target.txt"), linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := actions.ResolvePath(dir, "link.txt")
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestResolvePath_RejectsSymlinkInAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test uses POSIX semantics")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "child", "target.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := actions.ResolvePath(dir, "linkdir/child/target.txt")
	if err == nil {
		t.Fatal("expected error for path whose ancestor is a symlink, got nil")
	}
}

func TestResolvePath_AllowsNonExistentPath(t *testing.T) {
	dir := t.TempDir()

	got, err := actions.ResolvePath(dir, "does/not/exist.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, "does", "not", "exist.txt")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolvePath_RejectsNullByte(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "a\x00b")
	if err == nil {
		t.Fatal("expected error for path with null byte, got nil")
	}
	if !strings.Contains(err.Error(), "null byte") {
		t.Fatalf("expected null byte error, got %v", err)
	}
}

func TestResolvePath_RejectsSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test uses POSIX semantics")
	}
	real := t.TempDir()
	linkParent := t.TempDir()
	rootLink := filepath.Join(linkParent, "root_link")
	if err := os.Symlink(real, rootLink); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := actions.ResolvePath(rootLink, "a.txt")
	if err == nil {
		t.Fatal("expected error when repo root itself is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}
