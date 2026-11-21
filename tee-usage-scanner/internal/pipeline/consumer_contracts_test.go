package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func TestDeterministicContractIncludesConsumerDefinition(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"load.c": "struct key { int version; };\nvoid load(struct key *key) { key->version = 1; }\n", "guard.c": "int check_update_version(int version) { return version > 0; }\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "fact", Tool: "codeql", Operation: "cpp.state.rollback_version_propagation", RepoCommit: "rev", Status: "success",
		Findings: []artifacts.ToolFinding{{Location: artifacts.ToolLocation{Path: "load.c", StartLine: 2}, Related: []artifacts.ToolLocation{{Path: "load.c", Symbol: "load", StartLine: 2}, {Path: "guard.c", Symbol: "check_update_version", StartLine: 1}}}}}
	ref, err := trustirfacts.Persist(run, fact)
	if err != nil {
		t.Fatal(err)
	}
	table := &trustirfacts.FactTable{ProducedStructs: []string{"key"}, RollbackFields: []string{"version"}, RollbackAuthorities: []trustirfacts.RollbackAuthorityFact{{Function: "check_update_version"}}}
	pack := bindDeterministicContracts(artifacts.CasePack{}, fact, ref, table, run, root, "fixture", "rev")
	if len(pack.CaseInvariants) != 1 {
		t.Fatalf("contracts missing: %+v", pack)
	}
	c := pack.CaseInvariants[0]
	if len(c.Subjects) != 2 || c.Subjects[1].Symbol != "check_update_version" || c.Subjects[1].ContentSHA256 == "" {
		t.Fatalf("consumer anchor missing: %+v", c.Subjects)
	}
	if c.VerificationQueries[0].Parameters["subject"] != "load.c::load" {
		t.Fatal("consumer changed query target")
	}
}
