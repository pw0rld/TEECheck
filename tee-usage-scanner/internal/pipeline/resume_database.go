package pipeline

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// restoreFailedDatabase preserves the original index's database failure when a
// resumed run constructs a new in-memory database manager. A database becoming
// available later does not refresh the already-recorded program index, so this
// run must retain its degraded database semantics even if a DB now exists.
func restoreFailedDatabase(runDir string, manifest artifacts.Manifest, db interface {
	FreezeFailedScope(codedb.Scope, error)
}) error {
	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		return fmt.Errorf("resume database context: %w", err)
	}
	if facts.SchemaVersion != artifacts.SchemaVersionRepoFactsV1 {
		return fmt.Errorf("resume database context: unsupported or missing program-index schema %q", facts.SchemaVersion)
	}
	if manifest.RunID == "" || facts.RunID != manifest.RunID {
		return fmt.Errorf("resume database context: program-index run_id %q differs from manifest %q", facts.RunID, manifest.RunID)
	}
	if manifest.Scope.Root == "" || manifest.Scope.Hash == "" || facts.Scope != manifest.Scope {
		return fmt.Errorf("resume database context: program-index scope is missing or differs from manifest")
	}
	const failurePrefix = "codeql database: "
	if !strings.HasPrefix(facts.IndexNote, failurePrefix) {
		return nil
	}
	if strings.TrimSpace(strings.TrimPrefix(facts.IndexNote, failurePrefix)) == "" {
		return fmt.Errorf("resume database context: recorded database failure has no reason")
	}
	if db == nil {
		return fmt.Errorf("resume database context: database manager is unavailable")
	}
	db.FreezeFailedScope(codedb.Scope{
		RunDir: runDir, Repository: manifest.RepoURL, Commit: manifest.Commit,
	}, errors.New(facts.IndexNote))
	return nil
}
