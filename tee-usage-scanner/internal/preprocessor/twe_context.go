package preprocessor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twecontext"
)

// compileTWEKnowledge persists the complete prior-knowledge catalog for a run.
// Missing playbooks are tolerated during migration so old custom knowledge
// roots keep working; once the directory exists, malformed knowledge is fatal.
func compileTWEKnowledge(knowledgeRoot, runDir string) (bool, error) {
	dir := filepath.Join(knowledgeRoot, "twe", "playbooks")
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat playbook directory: %w", err)
	}
	catalog, err := twecontext.Load(dir)
	if err != nil {
		return false, err
	}
	compiled, err := catalog.Compile()
	if err != nil {
		return false, err
	}
	if err := runfs.WriteText(runfs.TWEAgentContextPath(runDir), compiled.Text); err != nil {
		return false, fmt.Errorf("write agent context: %w", err)
	}
	if err := runfs.WriteJSON(runfs.TWEKnowledgeManifestPath(runDir), compiled.Manifest); err != nil {
		return false, fmt.Errorf("write knowledge manifest: %w", err)
	}
	return true, nil
}
