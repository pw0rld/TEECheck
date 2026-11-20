package pipeline

import (
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func bindDeterministicContracts(pack artifacts.CasePack, fact artifacts.ToolFact, factPath string, table *trustirfacts.FactTable, runDir, root, repository, commit string) artifacts.CasePack {
	pack.ContractRequired = true
	if table == nil || len(table.ProducedStructs) != 1 || len(table.RollbackFields) != 1 {
		pack.CoverageGaps = append(pack.CoverageGaps, "No unambiguous struct/field binding for the deterministic contract.")
		return pack
	}
	binding := contracts.BindingContext{RunDir: runDir, RepoRoot: root, Scope: runfs.BuildScope(repository, commit, root)}
	if m, err := runfs.LoadManifest(runDir); err == nil {
		binding.Scope = m.Scope
	}
	for _, finding := range fact.Findings {
		if len(finding.Related) == 0 {
			continue
		}
		producer := finding.Related[0]
		if producer.Symbol == "" || producer.Path == "" {
			continue
		}
		field, typeName := table.RollbackFields[0], table.ProducedStructs[0]
		c := artifacts.CaseInvariantV2{Origin: "deterministic", Subjects: []artifacts.ContractSubject{{Path: producer.Path, Symbol: producer.Symbol}},
			Preconditions:    []string{"The named function and struct field are present in this source revision."},
			RequiredProperty: artifacts.ContractProperty{Kind: "direct_struct_field_assignment", Statement: fmt.Sprintf("%s contains a direct Assignment AST node to %s.%s", producer.Symbol, typeName, field), Destination: typeName + "." + field, TargetFields: []string{field}},
			SecurityEffect:   "The field contributes to the version value later considered by the state-acceptance guard; the complete dataflow requires separate review.",
			EvidenceRefs:     []artifacts.ContractEvidenceRef{{Kind: "tool_fact", Ref: factPath}}, RelatedTWEs: pack.RelatedTWEs,
			VerificationQueries: []artifacts.ContractQuery{{Backend: "codeql", Operation: verifier.StructFieldWriteOperation, Parameters: map[string]string{"type": typeName, "field": field}}}}
		bound, diagnostics, err := contracts.Bind(c, binding)
		if err != nil {
			pack.CoverageGaps = append(pack.CoverageGaps, "Contract binding: "+err.Error())
			continue
		}
		for _, d := range diagnostics {
			pack.CoverageGaps = append(pack.CoverageGaps, d.Message)
		}
		pack.CaseInvariants = append(pack.CaseInvariants, bound)
	}
	return pack
}
