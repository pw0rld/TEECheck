package reverify

import (
	"context"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceIdentity_ResolvesRevisionAndRejectsDirtyTree(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", root}, args...)...)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
		return string(out)
	}
	git("init", "-q")
	file := filepath.Join(root, "a.c")
	if err := os.WriteFile(file, []byte("int a;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "a.c")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
	cfg := config.Config{Commit: "HEAD"}
	mode, err := resolveSourceIdentity(context.Background(), root, &cfg)
	if err != nil || mode != "pinned_local_checkout" || cfg.Commit == "HEAD" {
		t.Fatalf("identity: %s %+v %v", mode, cfg, err)
	}
	cfg.Commit = "not-a-real-commit"
	if _, err := resolveSourceIdentity(context.Background(), root, &cfg); err == nil {
		t.Fatal("accepted nonexistent commit")
	}
	cfg.Commit = "HEAD"
	if err := os.WriteFile(file, []byte("int b;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSourceIdentity(context.Background(), root, &cfg); err == nil {
		t.Fatal("accepted dirty pinned source")
	}
}
func TestReverify_OutputCannotAlterSourceTree(t *testing.T) {
	cfg, _, _ := setupRecheck(t)
	cfg.OutputDir = filepath.Join(cfg.LocalPath, "contract-rechecks")
	if _, err := RunWithAssessment(context.Background(), cfg, nil); err == nil {
		t.Fatal("accepted output within scanned source")
	}
}
