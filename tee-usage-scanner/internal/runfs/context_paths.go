package runfs

import "path/filepath"

// ContextDir contains the canonical project-understanding artifacts shared by
// every security agent in a run. The directory is additive during migration:
// legacy run paths remain stable while new consumers move to these contracts.
func ContextDir(runDir string) string {
	return filepath.Join(runDir, "01_context")
}

func ArchitectureModelPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "architecture.v1.json")
}

// ArchitectureDossierPath is a derived human-readable view. The JSON model is
// the source of truth and must be written first.
func ArchitectureDossierPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "architecture_dossier.md")
}

func ProjectInvariantsPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "project_invariants.v1.json")
}

// TWEKnowledgeManifestPath pins the exact prior-knowledge context visible to
// the agents, making otherwise identical runs reproducible.
func TWEKnowledgeManifestPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "twe_knowledge_manifest.v1.json")
}

func TWEAgentContextPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "twe_agent_context.txt")
}

func BoundaryTopologyPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "boundary_topology.v1.json")
}

func ToolFactsDir(runDir string) string {
	return filepath.Join(runDir, "02_tool_facts")
}

func TrustIRToolFactsDir(runDir string) string {
	return filepath.Join(ToolFactsDir(runDir), "trustir")
}

func CodeQLToolFactsDir(runDir string) string {
	return filepath.Join(ToolFactsDir(runDir), "codeql")
}

func CallGraphToolFactsDir(runDir string) string {
	return filepath.Join(ToolFactsDir(runDir), "callgraph")
}

// TrustIRToolFactPath is the persisted location of one TrustIR ToolFact,
// named by its FactID. Mirrors InvestigationPath's runDir+id shape below.
func TrustIRToolFactPath(runDir, factID string) string {
	return filepath.Join(TrustIRToolFactsDir(runDir), factID+".json")
}

func InvestigationsDir(runDir string) string {
	return filepath.Join(runDir, "03_investigations")
}

func InvestigationPath(runDir, investigationID string) string {
	return filepath.Join(InvestigationsDir(runDir), investigationID+".json")
}
