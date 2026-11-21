package sourcehash

import (
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestTreeContentAndNames(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "a.c"), "same-size-a")
	put(t, filepath.Join(root, ".git", "index"), "ignored")
	first, err := Tree(root)
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(root, ".git", "index"), "changed")
	same, _ := Tree(root)
	if same != first {
		t.Fatal("VCS changes affected source hash")
	}
	put(t, filepath.Join(root, "a.c"), "same-size-b")
	changed, _ := Tree(root)
	if changed == first {
		t.Fatal("same-size content change was missed")
	}
	if err = os.Rename(filepath.Join(root, "a.c"), filepath.Join(root, "b.c")); err != nil {
		t.Fatal(err)
	}
	renamed, _ := Tree(root)
	if renamed == changed {
		t.Fatal("renaming file was missed")
	}
}
func TestTreeExcludesOnlyRunSubtree(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "a.c"), "a")
	run := filepath.Join(root, "out", "run")
	put(t, filepath.Join(run, "state.json"), "one")
	first, err := TreeExcluding(root, []string{run})
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(run, "state.json"), "two")
	second, _ := TreeExcluding(root, []string{run})
	if first != second {
		t.Fatal("run output changed source identity")
	}
}
func TestSymlinkBoundary(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "a.c"), "a")
	if err := os.Symlink("a.c", filepath.Join(root, "link.c")); err != nil {
		t.Fatal(err)
	}
	if _, err := Tree(root); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "outside.c")
	put(t, external, "outside")
	if err := os.Symlink(external, filepath.Join(root, "escape.c")); err != nil {
		t.Fatal(err)
	}
	if _, err := Tree(root); err == nil {
		t.Fatal("escaping symlink accepted")
	}
	if _, err := File(root, "escape.c"); err == nil {
		t.Fatal("escaping observed file accepted")
	}
}

func TestSymlinkedRootAndRunExclusion(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "source")
	run := filepath.Join(root, "run")
	put(t, filepath.Join(root, "a.c"), "a")
	put(t, filepath.Join(run, "state.json"), "one")
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	before, err := TreeExcluding(alias, []string{filepath.Join(alias, "run")})
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(run, "state.json"), "two")
	after, err := TreeExcluding(alias, []string{filepath.Join(alias, "run")})
	if err != nil || after != before {
		t.Fatalf("symlinked run exclusion failed: %v", err)
	}
	hashes, err := Files(alias, []string{filepath.Join(alias, "a.c")})
	if err != nil || hashes["a.c"] == "" {
		t.Fatalf("symlinked observation failed: %v", err)
	}
}
