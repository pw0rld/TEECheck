package runvalidate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Empty output directories are valid only for a genuinely empty case set.
// Each selected case must retain the evidence produced by every review stage.
func validateCaseOutputs(runDir string, add func(string, string, string, ...any)) {
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		add("case_outputs", runDir, "%v", err)
		return
	}
	for i, path := range paths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(path, &pack); err != nil || pack.CaseID == "" {
			add("case_outputs", path, "case has no readable identity: %v", err)
			continue
		}
		for _, stage := range []struct{ dir, prefix string }{{runfs.ExpertDir(runDir), "hypothesis"}, {runfs.ChallengerDir(runDir), "challenge"}, {runfs.VerifierDir(runDir), "verify"}} {
			output := filepath.Join(stage.dir, fmt.Sprintf("%s-%03d.json", stage.prefix, i+1))
			var artifact struct {
				CaseID string `json:"case_id"`
			}
			if err := runfs.ReadJSON(output, &artifact); err != nil {
				add("case_outputs", output, "required case review artifact missing: %v", err)
			} else if artifact.CaseID != pack.CaseID {
				add("case_outputs", output, "case_id %q differs from %q", artifact.CaseID, pack.CaseID)
			}
		}
		packetNames := []string{fmt.Sprintf("review-%03d.md", i+1)}
		if pack.ContractRequired || len(pack.CaseInvariants) > 0 {
			packetNames = nil
			for j := 0; j < max(1, len(pack.CaseInvariants)); j++ {
				packetNames = append(packetNames, fmt.Sprintf("review-%03d-contract-%03d.md", i+1, j+1))
			}
		}
		for _, name := range packetNames {
			path := filepath.Join(runfs.ArbiterPacketsDir(runDir), name)
			if _, err := os.Stat(path); err != nil {
				add("case_outputs", path, "case review packet is missing: %v", err)
			}
		}
	}
}
