package codedb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func cacheHash(s string) string {
	digest := sha256.Sum256([]byte(s))
	return hex.EncodeToString(digest[:])
}

func writeCacheJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".metadata-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func freezeTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm() & 0o555
		if d.IsDir() {
			mode |= 0o555
		} else {
			mode |= 0o444
		}
		return os.Chmod(path, mode)
	})
}

// Only caller-owned incomplete/temp trees are removed. Completed entries are
// never rewritten in place because active runs may still reference them.
func removeCacheTree(root string) error {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return err
	})
	return os.RemoveAll(root)
}

func contained(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// copyCacheTree intentionally copies bytes, never hardlinks. CodeQL analyze
// writes database caches and SARIF even when the query input is unchanged.
func copyCacheTree(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case d.Type()&os.ModeSymlink != 0:
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			if !contained(src, resolved) {
				return fmt.Errorf("database symlink escapes cached database: %s", rel)
			}
			resolvedRel, err := filepath.Rel(src, resolved)
			if err != nil {
				return err
			}
			link, err := filepath.Rel(filepath.Dir(target), filepath.Join(dst, resolvedRel))
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.Mode().IsRegular():
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()|0o600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, contextReader{ctx: ctx, reader: in})
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		default:
			return fmt.Errorf("unsupported database cache entry: %s", rel)
		}
	})
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
