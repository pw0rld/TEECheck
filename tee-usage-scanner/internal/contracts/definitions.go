// Package contracts binds logical security obligations to a particular source
// revision. It never derives a verdict from a missing query or missing symbol.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

type BindingContext struct {
	RunDir    string
	RepoRoot  string
	Scope     artifacts.ScannedScope
	RepoFacts *artifacts.RepoFacts
}
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Subject string `json:"subject,omitempty"`
}

func clone(c artifacts.CaseInvariantV2) artifacts.CaseInvariantV2 {
	data, _ := json.Marshal(c)
	var out artifacts.CaseInvariantV2
	_ = json.Unmarshal(data, &out)
	return out
}
func sortedUnique(v []string) []string {
	set := map[string]bool{}
	for _, s := range v {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LogicalDefinition deliberately removes every source-version observation,
// including old line numbers, hashes, evidence and proposer context.
func LogicalDefinition(c artifacts.CaseInvariantV2) artifacts.CaseInvariantV2 {
	out := clone(c)
	out.SchemaVersion = artifacts.SchemaVersionCaseInvariantV2
	out.Origin = "reverify"
	out.LeadRef = ""
	out.Scope = artifacts.ScannedScope{}
	out.EvidenceRefs = []artifacts.ContractEvidenceRef{}
	out.Grounding = "logical"
	for i, s := range out.Subjects {
		out.Subjects[i] = artifacts.ContractSubject{Path: s.Path, Symbol: s.Symbol}
	}
	out.DefinitionHash = DefinitionHash(out)
	return out
}

// DefinitionHash is independent of revision, origin, witnesses and line drift.
func DefinitionHash(c artifacts.CaseInvariantV2) string {
	subjects := make([]string, 0, len(c.Subjects))
	for _, s := range c.Subjects {
		subjects = append(subjects, s.Path+"\x00"+s.Symbol)
	}
	property := c.RequiredProperty
	property.TargetFields = sortedUnique(property.TargetFields)
	queries := append([]artifacts.ContractQuery{}, c.VerificationQueries...)
	sort.Slice(queries, func(i, j int) bool {
		a, _ := json.Marshal(queries[i])
		b, _ := json.Marshal(queries[j])
		return string(a) < string(b)
	})
	data, _ := json.Marshal(struct {
		Subjects, Preconditions []string
		Property                artifacts.ContractProperty
		SecurityEffect          string
		Queries                 []artifacts.ContractQuery
	}{sortedUnique(subjects), sortedUnique(c.Preconditions), property, c.SecurityEffect, queries})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PropertyKey separates independent checks even when they share one function.
func PropertyKey(c artifacts.CaseInvariantV2) string {
	subjects := make([]string, 0, len(c.Subjects))
	for _, s := range c.Subjects {
		subjects = append(subjects, s.Path+"::"+s.Symbol)
	}
	data, _ := json.Marshal(struct {
		Subjects                             []string
		Kind, Source, Destination, Authority string
		Targets                              []string
	}{sortedUnique(subjects), c.RequiredProperty.Kind, c.RequiredProperty.Source, c.RequiredProperty.Destination, c.RequiredProperty.Authority, sortedUnique(c.RequiredProperty.TargetFields)})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validateDefinition(c artifacts.CaseInvariantV2) error {
	if len(c.Subjects) == 0 {
		return fmt.Errorf("contract requires at least one subject")
	}
	for _, s := range c.Subjects {
		if strings.TrimSpace(s.Path) == "" || strings.TrimSpace(s.Symbol) == "" {
			return fmt.Errorf("subject path and symbol are required")
		}
	}
	if len(c.Preconditions) == 0 {
		return fmt.Errorf("contract requires explicit preconditions")
	}
	for _, p := range c.Preconditions {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("empty precondition")
		}
	}
	if strings.TrimSpace(c.RequiredProperty.Kind) == "" || strings.TrimSpace(c.RequiredProperty.Statement) == "" || strings.TrimSpace(c.SecurityEffect) == "" {
		return fmt.Errorf("property kind, statement and security effect are required")
	}
	switch c.Origin {
	case "planner", "deterministic", "both", "reverify":
	default:
		return fmt.Errorf("unsupported contract origin %q", c.Origin)
	}
	for _, q := range c.VerificationQueries {
		if q.Backend == "" || q.Operation == "" {
			return fmt.Errorf("query backend and registered operation are required")
		}
	}
	return nil
}

// Merge combines repeated observations of the SAME logical definition. The
// caller must retain both values when DefinitionHash differs.
func Merge(a, b artifacts.CaseInvariantV2) artifacts.CaseInvariantV2 {
	out := clone(a)
	if DefinitionHash(a) != DefinitionHash(b) {
		return out
	}
	if out.Origin != b.Origin && out.Origin != "reverify" && b.Origin != "reverify" {
		out.Origin = "both"
	}
	out.RelatedTWEs = sortedUnique(append(out.RelatedTWEs, b.RelatedTWEs...))
	seen := map[string]bool{}
	refs := []artifacts.ContractEvidenceRef{}
	for _, ref := range append(out.EvidenceRefs, b.EvidenceRefs...) {
		v, _ := json.Marshal(ref)
		if !seen[string(v)] {
			seen[string(v)] = true
			refs = append(refs, ref)
		}
	}
	out.EvidenceRefs = refs
	return out
}

func MergeAll(a, b []artifacts.CaseInvariantV2) []artifacts.CaseInvariantV2 {
	out := []artifacts.CaseInvariantV2{}
	indices := map[string]int{}
	for _, c := range append(append([]artifacts.CaseInvariantV2{}, a...), b...) {
		key := DefinitionHash(c)
		if i, ok := indices[key]; ok {
			out[i] = Merge(out[i], c)
		} else {
			indices[key] = len(out)
			out = append(out, clone(c))
		}
	}
	return out
}
