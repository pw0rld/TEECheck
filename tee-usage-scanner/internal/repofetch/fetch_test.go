package repofetch_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
)

func TestFetchLocalPath(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init")
	git(t, dir, "config", "user.email", "test@test.com")
	git(t, dir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "init")

	result, err := repofetch.Fetch(dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if result.LocalPath != dir {
		t.Fatalf("expected local path %s, got %s", dir, result.LocalPath)
	}
	if result.Commit == "" {
		t.Fatal("expected non-empty commit")
	}
	if result.Cloned {
		t.Fatal("expected Cloned=false for local path")
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo", true},
		{"http://example.com/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"/home/user/repo", false},
		{"./relative/path", false},
		{"repo-name", false},
	}
	for _, tt := range tests {
		got := repofetch.IsURL(tt.input)
		if got != tt.want {
			t.Errorf("IsURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
