package codeql

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AssembleFixtureCrate builds a compilable Rust crate in destDir by copying a
// fixture's CodeQL build harness (the skeleton crate: Cargo.toml, module tree,
// stub modules) and overlaying the variant's scan files on top. The result is
// ready for `codeql database create --language=rust`.
//
// harnessDir is the fixture's codeql/ skeleton; variantDir is the vulnerable/
// or fixed/ source root; scanPaths are the fixture's patched files (relative
// paths) to overlay. The cargo target/ directory is never copied.
func AssembleFixtureCrate(harnessDir, variantDir string, scanPaths []string, destDir string) error {
	if err := copyTree(harnessDir, destDir); err != nil {
		return fmt.Errorf("copy harness: %w", err)
	}
	for _, rel := range scanPaths {
		src := filepath.Join(variantDir, filepath.FromSlash(rel))
		dst := filepath.Join(destDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("overlay scan file %s: %w", rel, err)
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		// Never copy build output; it is large and machine-specific.
		if rel == "target" || strings.HasPrefix(rel, "target"+string(os.PathSeparator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
