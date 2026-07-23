package trustirfacts

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// materializeQueryPack copies the checked-in query pack (srcDir, e.g.
// codeql/trustir/cpp) into a per-run, per-operation directory and overwrites
// its common/GeneratedTrustFacts.qll with table's rendered clauses. The
// checked-in source tree is never written to — CodeQL only ever sees the
// materialized copy under the run directory.
//
// The destination is keyed by FactID so re-materializing an identical
// request is a harmless overwrite of identical content, not a growing pile
// of near-duplicate directories.
func materializeQueryPack(runDir, srcDir string, req Request, table FactTable) (packDir, queryFile string, err error) {
	queryRel, ok := operationQueries[req.Operation]
	if !ok {
		return "", "", fmt.Errorf("no query registered for operation %q", req.Operation)
	}

	packDir = filepath.Join(runfs.TrustIRToolFactsDir(runDir), "querypack", req.factID())
	if err := copyTree(srcDir, packDir); err != nil {
		return "", "", fmt.Errorf("copy query pack %s: %w", srcDir, err)
	}

	generated := filepath.Join(packDir, "common", "GeneratedTrustFacts.qll")
	if err := os.MkdirAll(filepath.Dir(generated), 0o755); err != nil {
		return "", "", fmt.Errorf("create common dir: %w", err)
	}
	if err := os.WriteFile(generated, []byte(table.Render()), 0o644); err != nil {
		return "", "", fmt.Errorf("write generated fact table: %w", err)
	}

	queryFile = filepath.Join(packDir, filepath.FromSlash(queryRel))
	if _, err := os.Stat(queryFile); err != nil {
		return "", "", fmt.Errorf("query file %s not found after copying %s: %w", queryRel, srcDir, err)
	}
	return packDir, queryFile, nil
}

// copyTree recursively copies src into dst, creating directories as needed.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
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
