package codedb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

type databaseMetadata struct {
	Schema               int    `json:"schema"`
	Key                  string `json:"key"`
	RepositoryHash       string `json:"repository_hash"`
	Commit               string `json:"commit"`
	SourceRoot           string `json:"source_root"`
	SourceTreeHash       string `json:"source_tree_hash"`
	CodeQLVersion        string `json:"codeql_version"`
	Language             string `json:"language"`
	BuildMode            string `json:"build_mode"`
	ExtractionConfigHash string `json:"extraction_config_hash"`
	DatabaseHash         string `json:"database_content_hash"`
}

func (m *Manager) databaseIdentity(ctx context.Context, b sourceBinding) (databaseMetadata, error) {
	v, ok := m.eng.(interface {
		Version(context.Context) (string, error)
	})
	if !ok {
		return databaseMetadata{}, fmt.Errorf("shared CodeQL cache requires an engine reporting its version")
	}
	version, err := v.Version(ctx)
	if err != nil {
		return databaseMetadata{}, fmt.Errorf("identify CodeQL cache version: %w", err)
	}
	if strings.TrimSpace(version) == "" {
		return databaseMetadata{}, fmt.Errorf("CodeQL version is empty")
	}
	// Extraction environment can change the fact database independently of the
	// revision. Persist only its digest; no environment values enter artifacts.
	env := []string{runtime.GOOS, runtime.GOARCH, m.extraPATH}
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(name, "CODEQL_EXTRACTOR_CPP_") || name == "CPATH" || name == "C_INCLUDE_PATH" || name == "CPLUS_INCLUDE_PATH" {
			env = append(env, value)
		}
	}
	sort.Strings(env)
	metadata := databaseMetadata{Schema: cacheSchema, RepositoryHash: b.RepositoryHash, Commit: b.Commit, SourceRoot: b.SourceRoot, SourceTreeHash: b.TreeHash, CodeQLVersion: strings.TrimSpace(version), Language: "cpp", BuildMode: "none", ExtractionConfigHash: cacheHash(strings.Join(env, "\x00"))}
	metadata.Key = cacheHash(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", metadata.Schema, metadata.RepositoryHash, metadata.Commit, metadata.SourceTreeHash, metadata.CodeQLVersion, metadata.Language, metadata.BuildMode, metadata.ExtractionConfigHash))
	return metadata, nil
}

func (m *Manager) ensureSharedDatabase(ctx context.Context, scope Scope) (string, error) {
	if _, err := m.EnsureSource(ctx, scope); err != nil {
		return "", err
	}
	source, err := m.readSourceBinding(scope)
	if err != nil {
		return "", err
	}
	wanted, err := m.databaseIdentity(ctx, source)
	if err != nil {
		return "", err
	}
	dbPath := m.Path(scope)
	unlock, err := lockCache(ctx, m.bindingPath(scope, "database")+".lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	var local databaseMetadata
	if err = readCacheJSON(m.bindingPath(scope, "database"), &local); err == nil && local.Key == wanted.Key && m.State(scope) == StateReady {
		return dbPath, ctx.Err()
	}
	unlockShared, err := lockCache(ctx, filepath.Join(m.cacheDir, "locks", "database-"+wanted.Key+".lock"))
	if err != nil {
		return "", err
	}
	defer unlockShared()
	entry := filepath.Join(m.cacheDir, "databases", wanted.Key)
	master := filepath.Join(entry, "db")
	var stored databaseMetadata
	if err = readCacheJSON(filepath.Join(entry, "database.json"), &stored); err == nil {
		identity := stored
		identity.DatabaseHash = ""
		if identity != wanted || !sha256Hex.MatchString(stored.DatabaseHash) {
			return "", fmt.Errorf("database cache metadata mismatch")
		}
		if _, err = os.Stat(filepath.Join(master, dbBuiltMarker)); err != nil {
			return "", fmt.Errorf("database cache completion marker missing: %w", err)
		}
		digest, err := sourcehash.Tree(master)
		if err != nil {
			return "", fmt.Errorf("verify database cache: %w", err)
		}
		if digest != stored.DatabaseHash {
			return "", fmt.Errorf("database cache content changed; refusing corrupted database")
		}
	} else if os.IsNotExist(err) {
		if err = removeCacheTree(entry); err != nil {
			return "", err
		}
		if err = os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
			return "", err
		}
		tmp, err := os.MkdirTemp(filepath.Dir(entry), ".database-*")
		if err != nil {
			return "", err
		}
		defer removeCacheTree(tmp)
		if err = m.buildDatabase(ctx, source.SourceRoot, filepath.Join(tmp, "db")); err != nil {
			return "", err
		}
		// Ensure the source has not been mutated during extraction. A readonly
		// cache is defence in depth; this digest is the consistency check.
		if err = validateSource(source); err != nil {
			return "", err
		}
		stored = wanted
		stored.DatabaseHash, err = sourcehash.Tree(filepath.Join(tmp, "db"))
		if err != nil {
			return "", err
		}
		if err = writeCacheJSON(filepath.Join(tmp, "database.json"), stored); err != nil {
			return "", err
		}
		if err = freezeTree(filepath.Join(tmp, "db")); err != nil {
			return "", err
		}
		if err = ctx.Err(); err != nil {
			return "", err
		}
		if err = os.Rename(tmp, entry); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("read completed database cache: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dbPath), ".database-copy-*")
	if err != nil {
		return "", err
	}
	defer removeCacheTree(tmp)
	if err = copyCacheTree(ctx, master, tmp); err != nil {
		return "", fmt.Errorf("copy private database: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = removeCacheTree(dbPath); err != nil {
		return "", err
	}
	if err = os.Rename(tmp, dbPath); err != nil {
		return "", err
	}
	if err = writeCacheJSON(m.bindingPath(scope, "database"), stored); err != nil {
		// Without the identity binding this copy must not appear reusable.
		_ = os.Remove(filepath.Join(dbPath, dbBuiltMarker))
		return "", err
	}
	return dbPath, nil
}
