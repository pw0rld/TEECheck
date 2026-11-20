package contracts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Evidence binding is deliberately independent of planner actions. Every
// evidence path is relative to its source/run root and may not traverse a link.
func resolvePath(root, relative string) (string, error) {
	if root == "" || relative == "" || strings.ContainsRune(relative, 0) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("evidence requires a relative path and a root")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("evidence path escapes root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("evidence root is a symlink")
	}
	current := abs
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err = os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("evidence path traverses a symlink")
		}
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("evidence path is not a regular file")
	}
	return current, nil
}
