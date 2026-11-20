package trustirfacts

// This file is the LLM annotation end of the fact layer §23.2 deferred out
// of the deterministic skeleton.
//
// The pipeline is Enumerate (enumerate.go, deterministic) -> Annotate (this
// file, LLM) -> resolveAnnotations (resolver.go, deterministic) -> FactTable
// (facttable.go's existing type, rendered exactly as the deterministic
// fixture is). AnnotateFactTable is the single entry point that runs all
// three steps; the caller binds its output to repository+commit through
// NewFactTableInput and supplies it explicitly in Request.

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// DefaultEnumRegistryPath is the checked-in enum vocabulary's conventional
// location, relative to the tee-usage-scanner module root — the mate of
// DefaultQueryPackDir (request.go). Callers wire it in explicitly, same
// reasoning as DefaultQueryPackDir: this package makes no assumption about
// the caller's working directory.
const DefaultEnumRegistryPath = "knowledge/twe/definitions/enum_registry.yml"

// maxPromptFunctionNames bounds each annotation call, never repository
// coverage. Every candidate appears in a chunk; later alphabetical names
// must be just as eligible for annotation as the first page.
const maxPromptFunctionNames = 300

// annotationSystemPrompt is the ONLY place this package tells the model
// what a claim_producer / rollback_authority annotation means. It
// deliberately does not restate the enum_registry.yml values — those are
// injected per-call from the loaded registry in buildAnnotationPrompt, so
// there is exactly one place in this codebase that lists them (§23.4.2).
const annotationSystemPrompt = `You are annotating C/C++ source code entities for a security fact-extraction pipeline (TrustIR-C, TWE-STATE-001 rollback family). Respond with a single JSON object matching the schema described in the user message, and nothing else — no prose, no markdown fences.

Every "role" and "kind" value you emit MUST be copied verbatim from the allowed-values lists given in the prompt. Inventing a role/kind value not in those lists is a fatal error for this pipeline — it will be discarded.

Every "function" name you emit MUST be copied verbatim from the candidate function list given in the prompt. Every value in "rollback_fields" MUST be copied verbatim from the candidate field list. Every value in "produced_structs" MUST be copied verbatim from the candidate struct list. Do not invent, guess, abbreviate, or paraphrase a name — an annotation naming something not in the given list will be discarded.

If you are not confident an entity belongs in a category, omit it rather than guessing.`

// annotationResponse is the wire shape this package asks the model for and
// parses with llm.ExtractJSONObject. Field names mirror FactTable's own
// field names (facttable.go) so resolveAnnotations (resolver.go) is a
// direct, unsurprising mapping from one to the other.
type annotationResponse struct {
	ClaimProducers []struct {
		Function string `json:"function"`
		Role     string `json:"role"`
	} `json:"claim_producers"`
	RollbackFields      []string `json:"rollback_fields"`
	ProducedStructs     []string `json:"produced_structs"`
	RollbackAuthorities []struct {
		Function string `json:"function"`
		Kind     string `json:"kind"`
	} `json:"rollback_authorities"`
}

// AnnotationReport is the diagnostic record of one AnnotateFactTable call:
// what was enumerated, what the LLM proposed, and what the resolver
// accepted vs rejected. Unresolved is always populated (possibly empty),
// never left for the caller to reconstruct — see resolver.go's doc comment
// on why rejections are recorded rather than silently dropped.
type AnnotationReport struct {
	Candidates  Candidates
	Unresolved  []UnresolvedAnnotation
	RawResponse string
	ChunkCount  int
}

// AnnotateFactTable is the LLM-driven end of the fact layer (§23.2/§23.3):
// enumerate candidate symbols from sourceRoot (Enumerate, enumerate.go),
// ask client to propose role/kind annotations constrained to registry, then
// verify every annotation resolves to a real enumerated symbol
// (resolveAnnotations, resolver.go) before it is allowed into the returned
// FactTable. Only resolved annotations reach the table; everything else is
// reported in AnnotationReport.Unresolved, never silently kept (§23.3).
//
// The caller may bind the result with NewFactTableInput and pass it to Run.
// This function does not register global state or alter another run's table.
func AnnotateFactTable(ctx context.Context, client llm.Client, registry twe.EnumRegistry, sourceRoot string) (FactTable, AnnotationReport, error) {
	cand, err := Enumerate(sourceRoot)
	if err != nil {
		return FactTable{}, AnnotationReport{}, fmt.Errorf("trustirfacts: enumerate %s: %w", sourceRoot, err)
	}
	report := AnnotationReport{Candidates: cand}

	if len(cand.Functions) == 0 {
		return FactTable{}, report, fmt.Errorf("trustirfacts: no function-like candidates enumerated under %s", sourceRoot)
	}
	if client == nil {
		return FactTable{}, report, fmt.Errorf("trustirfacts: no LLM client configured")
	}
	if err := registry.Validate(); err != nil {
		return FactTable{}, report, fmt.Errorf("trustirfacts: enum registry invalid: %w", err)
	}

	var combined annotationResponse
	var raw []string
	chunks := annotationChunks(cand)
	for i, chunk := range chunks {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: annotationSystemPrompt,
			Messages:     []llm.Message{{Role: "user", Content: buildAnnotationPrompt(chunk, registry)}},
			Temperature:  0,
			JSONMode:     true,
		})
		if err != nil {
			return FactTable{}, report, fmt.Errorf("trustirfacts: llm annotate chunk %d/%d: %w", i+1, len(chunks), err)
		}
		raw = append(raw, resp.Text)
		report.RawResponse = strings.Join(raw, "\n")
		report.ChunkCount++
		var parsed annotationResponse
		if err := llm.ExtractJSONObject(resp.Text, &parsed); err != nil {
			return FactTable{}, report, fmt.Errorf("trustirfacts: parse annotation response chunk %d/%d: %w", i+1, len(chunks), err)
		}
		// Resolve against precisely what this call saw, not the global set:
		// a name from a different chunk is still an ungrounded annotation.
		table, unresolved := resolveAnnotations(parsed, chunk, registry)
		report.Unresolved = append(report.Unresolved, unresolved...)
		for _, p := range table.ClaimProducers {
			combined.ClaimProducers = append(combined.ClaimProducers, struct {
				Function string `json:"function"`
				Role     string `json:"role"`
			}{p.Function, p.Role})
		}
		for _, a := range table.RollbackAuthorities {
			combined.RollbackAuthorities = append(combined.RollbackAuthorities, struct {
				Function string `json:"function"`
				Kind     string `json:"kind"`
			}{a.Function, a.Kind})
		}
		combined.RollbackFields = append(combined.RollbackFields, table.RollbackFields...)
		combined.ProducedStructs = append(combined.ProducedStructs, table.ProducedStructs...)
	}
	table, _ := resolveAnnotations(combined, cand, registry)
	// Canonical order makes a table's identity independent of chunk or
	// response ordering, including paired vulnerable/fixed revisions.
	sort.Slice(table.ClaimProducers, func(i, j int) bool {
		a, b := table.ClaimProducers[i], table.ClaimProducers[j]
		return a.Function+"\x00"+a.Role < b.Function+"\x00"+b.Role
	})
	sort.Slice(table.RollbackAuthorities, func(i, j int) bool {
		a, b := table.RollbackAuthorities[i], table.RollbackAuthorities[j]
		return a.Function+"\x00"+a.Kind < b.Function+"\x00"+b.Kind
	})
	sort.Strings(table.RollbackFields)
	sort.Strings(table.ProducedStructs)
	return table, report, nil
}

// annotationChunks interleaves modules before paging, so a large library
// cannot monopolize the first call. All functions remain represented.
func annotationChunks(cand Candidates) []Candidates {
	groups := map[string][]FunctionCandidate{}
	for _, fn := range cand.Functions {
		module := ""
		if len(fn.Files) > 0 {
			files := append([]string(nil), fn.Files...)
			sort.Strings(files)
			module = filepath.Dir(files[0])
		}
		groups[module] = append(groups[module], fn)
	}
	modules := make([]string, 0, len(groups))
	for module := range groups {
		modules = append(modules, module)
		sort.Slice(groups[module], func(i, j int) bool { return groups[module][i].Name < groups[module][j].Name })
	}
	sort.Strings(modules)
	ordered := make([]FunctionCandidate, 0, len(cand.Functions))
	for offset := 0; len(ordered) < len(cand.Functions); offset++ {
		for _, module := range modules {
			if offset < len(groups[module]) {
				ordered = append(ordered, groups[module][offset])
			}
		}
	}
	var chunks []Candidates
	for start := 0; start < len(ordered); start += maxPromptFunctionNames {
		end := min(start+maxPromptFunctionNames, len(ordered))
		chunks = append(chunks, Candidates{Functions: ordered[start:end], Fields: cand.Fields, Structs: cand.Structs})
	}
	return chunks
}

// buildAnnotationPrompt renders the candidate lists (Enumerate's output)
// and the allowed role/kind vocabulary (loaded from registry — never
// hardcoded here, §23.4.2) into the single user-turn prompt AnnotateFactTable
// sends. Only the two categories this first slice's operation
// (OperationRollbackVersionPropagation) uses — claim_field_role and
// authority_kind — are included; a future family adds its own categories
// here without touching the ones already wired.
func buildAnnotationPrompt(cand Candidates, registry twe.EnumRegistry) string {
	var b strings.Builder

	b.WriteString("Candidate function/callable names found in this repository (choose ONLY from this list for \"function\" fields):\n")
	names := candidateFunctionNames(cand)
	writeList(&b, names)

	b.WriteString("\nCandidate field names found via member access, e.g. `x->field` or `x.field` (choose ONLY from this list for \"rollback_fields\"):\n")
	writeList(&b, cand.Fields)

	b.WriteString("\nCandidate struct type names found (choose ONLY from this list for \"produced_structs\"):\n")
	writeList(&b, cand.Structs)

	b.WriteString("\nAllowed \"role\" values for claim_producers (claim_field_role, from knowledge/twe/definitions/enum_registry.yml):\n")
	writeList(&b, registry["claim_field_role"])

	b.WriteString("\nAllowed \"kind\" values for rollback_authorities (authority_kind, from knowledge/twe/definitions/enum_registry.yml):\n")
	writeList(&b, registry["authority_kind"])

	b.WriteString(`
Return a JSON object shaped exactly like this (omit an array entirely, or leave it empty, if you found nothing for it):
{
  "claim_producers": [{"function": "<name from the function list>", "role": "<value from claim_field_role>"}],
  "rollback_fields": ["<name from the field list>"],
  "produced_structs": ["<name from the struct list>"],
  "rollback_authorities": [{"function": "<name from the function list>", "kind": "<value from authority_kind>"}]
}

A "claim_producer" is a function that fills a claim-bearing output (e.g. it copies fields into a struct passed as an output pointer). A "rollback_authority" is a function that consumes a version/state field to accept or reject a rollback/downgrade. "rollback_fields" are the specific field name(s) that carry that version/state value into the output. "produced_structs" are the struct type name(s) the producer fills.
`)
	return b.String()
}

func writeList(b *strings.Builder, values []string) {
	if len(values) == 0 {
		b.WriteString("(none found)\n")
		return
	}
	for _, v := range values {
		b.WriteString("- ")
		b.WriteString(v)
		b.WriteString("\n")
	}
}

func candidateFunctionNames(cand Candidates) []string {
	out := make([]string, 0, len(cand.Functions))
	for _, f := range cand.Functions {
		out = append(out, f.Name)
	}
	return out // Enumerate already returns Functions sorted by Name.
}
