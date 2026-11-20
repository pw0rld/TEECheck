package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSearchKeywordsRejectsEscapingPaths(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("PRIVATE_MARKER\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside.txt", outside, "escape", "../missing.txt", filepath.Join(parent, "missing.txt")} {
		t.Run(path, func(t *testing.T) {
			hits, err := NewLocalAdapter().SearchKeywords(context.Background(), root, []string{path}, []string{"PRIVATE_MARKER"}, 8)
			if err == nil {
				t.Fatalf("escaping target %q accepted: %+v", path, hits)
			}
			if len(hits) != 0 {
				t.Fatalf("outside data leaked: %+v", hits)
			}
		})
	}
}

func TestSearchKeywordsWalkSkipsExternalSymlinkAndAcceptsRootAlias(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("MARKER inside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("MARKER outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	hits, err := NewLocalAdapter().SearchKeywords(context.Background(), alias, nil, []string{"MARKER"}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Path != "inside.txt" {
		t.Fatalf("want only in-root hit, got %+v", hits)
	}
}
