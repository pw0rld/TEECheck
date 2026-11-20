package trustirfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func digestQueryPack(root string) (string, error) {
	hash := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() == queryPackMarker {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("query pack contains non-regular file")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(hash, "%s\x00%x\n", filepath.ToSlash(rel), sum)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

const queryPackMarker = ".querypack-ready"

// materializeQueryPack publishes an immutable, complete query-pack directory.
// Its identity covers the actual source pack and table, including direct
// callers whose Request has not yet recorded those digests.
func materializeQueryPack(runDir, srcDir string, req Request, table FactTable) (packDir, queryFile string, err error) {
	queryRel, ok := operationQueries[req.Operation]
	if !ok {
		return "", "", fmt.Errorf("no query registered for operation %q", req.Operation)
	}
	sourceHash, err := digestQueryPack(srcDir)
	if err != nil {
		return "", "", err
	}
	tableHash, err := tableDigest(table)
	if err != nil {
		return "", "", err
	}
	keySum := sha256.Sum256([]byte(req.argumentsSHA256() + "\x00" + sourceHash + "\x00" + tableHash))
	key := hex.EncodeToString(keySum[:])
	packDir = filepath.Join(runfs.TrustIRToolFactsDir(runDir), "querypack", key[:24])
	queryFile = filepath.Join(packDir, filepath.FromSlash(queryRel))
	checkPublished := func() error {
		marker, err := os.ReadFile(filepath.Join(packDir, queryPackMarker))
		if err != nil {
			return err
		}
		fields := strings.Fields(string(marker))
		if len(fields) != 2 || fields[0] != key {
			return fmt.Errorf("query pack has invalid publication identity")
		}
		got, err := digestQueryPack(packDir)
		if err != nil {
			return err
		}
		if got != fields[1] {
			return fmt.Errorf("published query pack content changed")
		}
		_, err = os.Stat(queryFile)
		return err
	}
	if _, err := os.Stat(packDir); err == nil {
		if err := checkPublished(); err != nil {
			return "", "", err
		}
		return packDir, queryFile, nil
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(packDir), 0755); err != nil {
		return "", "", err
	}
	temp, err := os.MkdirTemp(filepath.Dir(packDir), ".querypack-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(temp)
	if err := copyTree(srcDir, temp); err != nil {
		return "", "", err
	}
	generated := filepath.Join(temp, "common", "GeneratedTrustFacts.qll")
	if err := os.MkdirAll(filepath.Dir(generated), 0755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(generated, []byte(table.Render()), 0644); err != nil {
		return "", "", err
	}
	if _, err := os.Stat(filepath.Join(temp, filepath.FromSlash(queryRel))); err != nil {
		return "", "", err
	}
	materializedHash, err := digestQueryPack(temp)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(temp, queryPackMarker), []byte(key+"\n"+materializedHash+"\n"), 0644); err != nil {
		return "", "", err
	}
	if err := os.Rename(temp, packDir); err != nil {
		if readyErr := checkPublished(); readyErr != nil {
			return "", "", fmt.Errorf("publish query pack: %w", err)
		}
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
