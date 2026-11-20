package reverify

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func resolveSourceIdentity(ctx context.Context, root string, cfg *config.Config) (string, error) {
	command := func(args ...string) (string, error) {
		base := []string{"--no-optional-locks", "-C", root}
		out, err := exec.CommandContext(ctx, "git", append(base, args...)...).Output()
		return strings.TrimSpace(string(out)), err
	}
	top, err := command("rev-parse", "--show-toplevel")
	actualRoot, rootErr := filepath.EvalSymlinks(root)
	actualTop, topErr := filepath.EvalSymlinks(top)
	if err != nil || rootErr != nil || topErr != nil || actualRoot != actualTop {
		if cfg.Commit == "" || cfg.Commit == "unknown" {
			return "", fmt.Errorf("a non-repository source requires an explicit --commit label")
		}
		return "local_partial", nil
	}
	head, err := command("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", fmt.Errorf("resolve source HEAD: %w", err)
	}
	if cfg.Commit != "" {
		expected, err := command("rev-parse", "--verify", "--end-of-options", cfg.Commit+"^{commit}")
		if err != nil {
			return "", fmt.Errorf("resolve --commit against source repository: %w", err)
		}
		if head != expected {
			return "", fmt.Errorf("source HEAD does not match --commit; check out the desired revision before re-verifying")
		}
	}
	dirty, err := command("status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return "", fmt.Errorf("check source state: %w", err)
	}
	if dirty != "" {
		return "", fmt.Errorf("source has tracked modifications; re-verification requires a clean pinned checkout")
	}
	cfg.Commit = head
	return "pinned_local_checkout", nil
}
