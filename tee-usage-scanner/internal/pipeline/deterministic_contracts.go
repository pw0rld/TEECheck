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
	var index artifacts.RepoFacts
	if runfs.ReadJSON(runfs.RepoFactsPath(runDir), &index) == nil {
		binding.RepoFacts = &index
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
			VerificationQueries: []artifacts.ContractQuery{{Backend: "codeql", Operation: verifier.StructFieldWriteOperation, Parameters: map[string]string{"type": typeName, "field": field, "subject": producer.Path + "::" + producer.Symbol}}}}
		for _, authority := range table.RollbackAuthorities {
			if authority.Function == producer.Symbol {
				continue
			}
			subject, ok := consumerSubject(authority.Function, finding.Related, pack.Snippets, binding)
			if ok {
				c.Subjects = append(c.Subjects, subject)
			} else {
				pack.CoverageGaps = append(pack.CoverageGaps, "Consumer definition could not be uniquely bound: "+authority.Function)
			}
		}
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

func consumerSubject(symbol string, related []artifacts.ToolLocation, snippets []artifacts.PromptSnippet, binding contracts.BindingContext) (artifacts.ContractSubject, bool) {
	paths := map[string]bool{}
	for _, loc := range related {
		if loc.Symbol == symbol {
			paths[loc.Path] = true
		}
	}
	for _, snippet := range snippets {
		paths[snippet.Path] = true
	}
	if binding.RepoFacts != nil {
		for _, s := range binding.RepoFacts.Symbols {
			if s.Name == symbol || s.QualifiedName == symbol {
				paths[s.File] = true
			}
		}
	}
	var resolved []artifacts.ContractSubject
	for path := range paths {
		if path == "" {
			continue
		}
		if subject, err := contracts.BindSubject(artifacts.ContractSubject{Path: path, Symbol: symbol}, binding); err == nil {
			resolved = append(resolved, subject)
		}
	}
	if len(resolved) != 1 {
		return artifacts.ContractSubject{}, false
	}
	return resolved[0], true
}
