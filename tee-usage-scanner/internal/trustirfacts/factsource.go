package trustirfacts

import "fmt"

// FactTableInput binds explicit, immutable annotation input to one revision.
// No process-global annotation registry is used.
type FactTableInput struct {
	Repository string
	Commit     string
	Source     string
	Table      FactTable
}

func NewFactTableInput(repository, commit string, table FactTable, source string) *FactTableInput {
	return &FactTableInput{Repository: repository, Commit: commit, Source: source, Table: cloneFactTable(table)}
}

func cloneFactTable(table FactTable) FactTable {
	return FactTable{
		ClaimProducers:      append([]ClaimProducerFact(nil), table.ClaimProducers...),
		RollbackFields:      append([]string(nil), table.RollbackFields...),
		ProducedStructs:     append([]string(nil), table.ProducedStructs...),
		RollbackAuthorities: append([]RollbackAuthorityFact(nil), table.RollbackAuthorities...),
	}
}

func (req Request) resolveFactTable() (FactTable, string, bool, error) {
	if req.FactTable != nil {
		in := req.FactTable
		if normalizeRepo(in.Repository) != normalizeRepo(req.Repository) || in.Commit != req.Commit {
			return FactTable{}, "", false, fmt.Errorf("fact table is bound to a different repository or commit")
		}
		if in.Source != "llm_annotated" && in.Source != "shipped_fixture" {
			return FactTable{}, "", false, fmt.Errorf("fact table source must be llm_annotated or shipped_fixture")
		}
		return cloneFactTable(in.Table), in.Source, true, nil
	}
	table, ok := factTableFor(req.Repository)
	return table, "shipped_fixture", ok, nil
}
