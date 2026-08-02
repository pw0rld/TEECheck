package runfs

import (
	"path/filepath"
	"testing"
)

func TestContextPathsStayUnderRunDir(t *testing.T) {
	runDir := filepath.Join("tmp", "runs", "run-1")
	wants := map[string]string{
		ArchitectureModelPath(runDir):     filepath.Join(runDir, "01_context", "architecture.v1.json"),
		ArchitectureDossierPath(runDir):   filepath.Join(runDir, "01_context", "architecture_dossier.md"),
		ProjectInvariantsPath(runDir):     filepath.Join(runDir, "01_context", "project_invariants.v1.json"),
		TWEKnowledgeManifestPath(runDir):  filepath.Join(runDir, "01_context", "twe_knowledge_manifest.v1.json"),
		TWEAgentContextPath(runDir):       filepath.Join(runDir, "01_context", "twe_agent_context.txt"),
		TrustIRToolFactsDir(runDir):       filepath.Join(runDir, "02_tool_facts", "trustir"),
		CodeQLToolFactsDir(runDir):        filepath.Join(runDir, "02_tool_facts", "codeql"),
		CallGraphToolFactsDir(runDir):     filepath.Join(runDir, "02_tool_facts", "callgraph"),
		InvestigationPath(runDir, "rb-1"): filepath.Join(runDir, "03_investigations", "rb-1.json"),
	}
	for got, want := range wants {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}
