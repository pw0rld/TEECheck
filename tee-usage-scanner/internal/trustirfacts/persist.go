package trustirfacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// Persist publishes a complete validated result without replacing an existing
// identity. Identical repeats are idempotent; different content must receive a
// different execution identity rather than silently reusing stale evidence.
func Persist(runDir string, fact artifacts.ToolFact) (string, error) {
	data, err := json.MarshalIndent(fact, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal tool fact: %w", err)
	}
	if err := schema.Validate(schema.TrustIRToolV1, data); err != nil {
		return "", fmt.Errorf("tool fact %s failed schema validation: %w", fact.FactID, err)
	}
	path := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if _, err := os.Stat(path); err == nil {
		return samePersistedFact(path, fact)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tool-fact-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0644); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	// Linking a completed sibling file publishes atomically and cannot replace
	// the winner of another concurrent publish of the same immutable identity.
	if err := os.Link(tmp.Name(), path); err != nil {
		if os.IsExist(err) {
			return samePersistedFact(path, fact)
		}
		return "", fmt.Errorf("publish tool fact: %w", err)
	}
	return path, nil
}

func samePersistedFact(path string, fact artifacts.ToolFact) (string, error) {
	var existing artifacts.ToolFact
	if err := runfs.ReadJSON(path, &existing); err != nil {
		return "", fmt.Errorf("existing tool fact %s is unreadable: %w", fact.FactID, err)
	}
	oldJSON, oldErr := json.Marshal(existing)
	newJSON, newErr := json.Marshal(fact)
	if oldErr != nil || newErr != nil || string(oldJSON) != string(newJSON) {
		return "", fmt.Errorf("tool fact %s already persisted with different content or a different fact table; use a distinct execution identity", fact.FactID)
	}
	return path, nil
}
