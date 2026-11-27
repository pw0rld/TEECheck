// Package contractreview performs source-grounded, per-contract reviews. A
// review is an agent opinion; only the verifier may turn tool execution into
// an InvariantAssessment.
package contractreview

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Review never accepts a model-supplied assessment or tool result. Peer reviews
// are supplied only to the verifier; the independent reviewers receive none.
func Review(ctx context.Context, client llm.Client, role string, binding contracts.BindingContext, c artifacts.CaseInvariantV2, peers []artifacts.ContractReview, temperature float64, facts ...artifacts.ToolFact) (artifacts.ContractReview, error) {
	if c.Grounding != "source_bound" {
		return unresolved(c.InvariantID, "contract has no validated source binding"), nil
	}
	if err := contracts.Validate(c, binding); err != nil {
		return unresolved(c.InvariantID, "contract binding failed: "+err.Error()), nil
	}
	// Contracts reference the immutable trace artifact; never rely on a model
	// copying a path summary into its own conclusions. The same source facts
	// are available independently to Expert, Challenger and Verifier.
	seenFacts := map[string]bool{}
	for _, fact := range facts {
		seenFacts[fact.FactID] = true
	}
	for _, ref := range c.EvidenceRefs {
		if ref.Kind != "tool_fact" {
			continue
		}
		fact, err := contracts.LoadToolFact(ref.Ref, binding)
		if err != nil {
			return unresolved(c.InvariantID, "contract tool evidence failed: "+err.Error()), nil
		}
		if !seenFacts[fact.FactID] {
			facts = append(facts, fact)
			seenFacts[fact.FactID] = true
		}
	}
	if client == nil {
		return unresolved(c.InvariantID, "review client unavailable"), nil
	}
	source, err := sourceContext(binding.RepoRoot, c)
	if err != nil {
		return unresolved(c.InvariantID, err.Error()), nil
	}
	definition, _ := json.Marshal(c)
	peerJSON, _ := json.Marshal(peers)
	system := `You review a defensive source-code contract for TEECheck. Evaluate only the supplied contract and code, without inventing tool executions or drawing conclusions about other contracts.
Return one JSON object with fields: invariant_id, position (supported|contradicted|unresolved), reason, preconditions_satisfied (boolean), attack_chain_complete (boolean), witness (array of {path,symbol,start_line,end_line}), counter_evidence (array of strings).
"supported" means the source supports a security-relevant violation of the required property under its preconditions, not that the code satisfies the property. Explain how it affects the stated security decision. A syntactic difference alone does not establish a security issue. "contradicted" means the proposed violation has contrary evidence. These are source-review opinions, not deterministic proof.
Set preconditions_satisfied only when every necessary precondition has source support. Set attack_chain_complete only when the relevant input, property violation and security effect are connected by evidence; do not infer completeness from missing objections. Identify each unresolved relation explicitly. A witness must cite actual lines within this contract's supplied source anchors. Put ONLY concrete source code that contradicts or mitigates the claimed violation into counter_evidence; when position is "supported" and no contradicting guard exists, leave counter_evidence as an empty array [] (do NOT put supporting observations or generic disclaimers in counter_evidence). Do not use a conclusion about another contract as evidence.`
	system += "\nThe query parameters identify the local property target; the other subjects provide consumer/caller context for preconditions and effects. Judge the property separately from missing runtime context. A successful registered local query is not invalidated merely because cross-function preconditions are unproved; record those gaps honestly."
	user := fmt.Sprintf("Role: %s\nContract:\n%s\nSource anchors:\n%s", role, definition, source)
	if extra := surroundingSourceContext(binding, c); extra != "" {
		user += "\nAdditional verified repository context (use this to check callers, callees, and preconditions; cite ONLY Source anchors above in witness):\n" + extra
	}
	factsOmitted := false
	if len(peers) > 0 {
		user += "\nIndependent per-contract review opinions (check against the code):\n" + string(peerJSON)
	}
	if len(facts) > 0 {
		var evidence strings.Builder
		omitted := 0
		for _, fact := range facts {
			var rendered string
			if fact.Operation == artifacts.TaintTraceOperation {
				rendered = artifacts.FormatToolFact(fact)
			} else {
				data, _ := json.Marshal(fact)
				rendered = string(data)
			}
			if evidence.Len()+len(rendered) > 32*1024 {
				omitted++
				continue
			}
			evidence.WriteString(rendered)
			evidence.WriteByte('\n')
		}
		if omitted > 0 {
			factsOmitted = true
			fmt.Fprintf(&evidence, "%d additional immutable fact(s) omitted from this prompt; references remain in the contract. Do not infer their contents.\n", omitted)
		}
		user += "\nExecutor observations (immutable; not verdicts; do not claim other tools ran):\n" + evidence.String()
		user += "\nTaint paths describe possible flow in the configured static model. No paths or configured barrier filters do not establish safety. Confirm the actual guards and data relationships in source."
	}
	var review artifacts.ContractReview
	_, err = llm.GenerateJSON(ctx, client, role, llm.GenerateRequest{
		SystemPrompt: system, Messages: []llm.Message{{Role: "user", Content: user}},
		Temperature: temperature, JSONMode: true,
	}, &review)
	if err != nil {
		return artifacts.ContractReview{}, err
	}
	if factsOmitted {
		review.Position = "unresolved"
		review.AttackChainComplete = false
		review.Reason += " Some referenced tool evidence exceeded the review prompt budget."
	}
	return ValidateReview(review, c, binding), nil
}

// ValidateReview checks ownership and fresh source anchors before an opinion
// may contribute to a source-corroborated finding.
func ValidateReview(r artifacts.ContractReview, c artifacts.CaseInvariantV2, binding contracts.BindingContext) artifacts.ContractReview {
	if r.InvariantID != c.InvariantID {
		return unresolved(c.InvariantID, "review names a different contract")
	}
	switch r.Position {
	case "supported", "contradicted", "unresolved":
	default:
		return unresolved(c.InvariantID, "invalid review position")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return unresolved(c.InvariantID, "review has no explanation")
	}
	for i, witness := range r.Witness {
		if !withinContract(witness, c) {
			return unresolved(c.InvariantID, "witness is outside this contract's source anchors")
		}
		bound, err := contracts.BindSubject(witness, binding)
		if err != nil {
			return unresolved(c.InvariantID, "witness binding failed: "+err.Error())
		}
		r.Witness[i] = bound
	}
	if r.Position != "unresolved" && len(r.Witness) == 0 {
		return unresolved(c.InvariantID, "source review has no anchored witness")
	}
	if len(r.CounterEvidence) > 0 && r.Position == "supported" {
		r.Position = "unresolved"
		r.AttackChainComplete = false
	}
	return r
}

func withinContract(w artifacts.ContractSubject, c artifacts.CaseInvariantV2) bool {
	for _, s := range c.Subjects {
		if filepath.ToSlash(w.Path) == filepath.ToSlash(s.Path) && w.Symbol == s.Symbol &&
			w.StartLine >= s.StartLine && w.EndLine >= w.StartLine && w.EndLine <= s.EndLine {
			return true
		}
	}
	return false
}

func unresolved(id, reason string) artifacts.ContractReview {
	return artifacts.ContractReview{InvariantID: id, Position: "unresolved", Reason: reason}
}

func sourceContext(root string, c artifacts.CaseInvariantV2) (string, error) {
	var out strings.Builder
	for _, s := range c.Subjects {
		if _, err := contracts.BindSubject(s, contracts.BindingContext{RepoRoot: root, Scope: c.Scope}); err != nil {
			return "", fmt.Errorf("invalid source anchor: %w", err)
		}
		data, err := os.ReadFile(filepath.Join(root, s.Path))
		if err != nil {
			return "", fmt.Errorf("read source anchor: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		if s.StartLine < 1 || s.EndLine < s.StartLine || s.EndLine > len(lines) {
			return "", fmt.Errorf("invalid source range for %s", s.Path)
		}
		fmt.Fprintf(&out, "\n%s :: %s\n", s.Path, s.Symbol)
		for n := s.StartLine; n <= s.EndLine; n++ {
			fmt.Fprintf(&out, "%d: %s\n", n, lines[n-1])
		}
		if out.Len() > 48*1024 {
			return "", fmt.Errorf("contract source exceeds review byte budget")
		}
	}
	return out.String(), nil
}

// Find returns only an unambiguous opinion for this contract. Duplicate model
// entries must not make the last answer silently win.
func Find(reviews []artifacts.ContractReview, id string) (artifacts.ContractReview, bool) {
	var found artifacts.ContractReview
	count := 0
	for _, r := range reviews {
		if r.InvariantID == id {
			found, count = r, count+1
		}
	}
	return found, count == 1
}

// surroundingSourceContext attaches verified surrounding file lines (±100 lines
// around each subject) and up to 6 1-hop caller/callee definitions from the
// repository index so Expert, Challenger, and Verifier can evaluate cross-function
// preconditions and downstream guards without being blinded by narrow 5-line
// subject anchors. Witnesses are still strictly restricted to c.Subjects.
func surroundingSourceContext(binding contracts.BindingContext, c artifacts.CaseInvariantV2) string {
	if binding.RepoRoot == "" || len(c.Subjects) == 0 {
		return ""
	}
	const maxExtraBytes = 32 * 1024
	var out strings.Builder
	includedSpans := map[string][][2]int{}
	for _, s := range c.Subjects {
		p := filepath.ToSlash(s.Path)
		includedSpans[p] = append(includedSpans[p], [2]int{s.StartLine, s.EndLine})
	}

	appendSpan := func(header, relPath string, startLine, endLine int) {
		if out.Len() >= maxExtraBytes || relPath == "" {
			return
		}
		full, err := contextSourcePath(binding.RepoRoot, relPath)
		if err != nil {
			return
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) == 0 {
			return
		}
		if startLine < 1 {
			startLine = 1
		}
		if endLine > len(lines) {
			endLine = len(lines)
		}
		if endLine < startLine {
			return
		}
		// Avoid duplicating exact lines already shown in anchors or earlier context.
		p := filepath.ToSlash(relPath)
		for _, sp := range includedSpans[p] {
			if startLine >= sp[0] && endLine <= sp[1] {
				return
			}
		}
		const omittedNotice = "[additional context omitted by byte budget; absence proves nothing]\n"
		// Reserve the full header and an explicit omission note before adding
		// whole source lines. Never claim a range whose tail was not rendered.
		headerBudget := len(fmt.Sprintf("\n%s (%s:%d-%d)\n", header, relPath, startLine, endLine))
		var body strings.Builder
		lastLine := startLine - 1
		for n := startLine; n <= endLine; n++ {
			line := fmt.Sprintf("%d: %s\n", n, lines[n-1])
			if out.Len()+headerBudget+body.Len()+len(line)+len(omittedNotice) > maxExtraBytes {
				break
			}
			body.WriteString(line)
			lastLine = n
		}
		if lastLine < startLine {
			return
		}
		fmt.Fprintf(&out, "\n%s (%s:%d-%d)\n", header, relPath, startLine, lastLine)
		out.WriteString(body.String())
		if lastLine < endLine {
			out.WriteString(omittedNotice)
		}
		includedSpans[p] = append(includedSpans[p], [2]int{startLine, lastLine})
	}

	// 1. Surrounding lines in each subject file. For compact files (<= 650 lines),
	// include the full file so entry points and same-file callers (e.g. SMC/syscall
	// dispatchers further down the file) are visible when checking preconditions.
	seenFile := map[string]bool{}
	for _, s := range c.Subjects {
		p := filepath.ToSlash(s.Path)
		if seenFile[p] {
			continue
		}
		seenFile[p] = true
		lo := s.StartLine - 100
		hi := s.EndLine + 160
		if full, err := contextSourcePath(binding.RepoRoot, s.Path); err == nil {
			if data, err := os.ReadFile(full); err == nil {
				lineCount := strings.Count(string(data), "\n") + 1
				if lineCount <= 650 && len(data) <= 20*1024 {
					lo = 1
					hi = lineCount
				}
			}
		}
		appendSpan("Surrounding file context", s.Path, lo, hi)
	}

	// 2. Exact SymbolID-based 1-hop callers/callees from RepoFacts when RunDir is present.
	// Locate subjects strictly by (path, symbol, overlapping line range) so same-name static
	// functions in different files never cross-contaminate CallEdges or StructFieldBridges.
	if binding.RunDir != "" && out.Len() < maxExtraBytes {
		var facts artifacts.RepoFacts
		manifest, manifestErr := runfs.LoadManifest(binding.RunDir)
		if err := runfs.ReadJSON(runfs.RepoFactsPath(binding.RunDir), &facts); err == nil &&
			manifestErr == nil && manifest.RunID != "" && facts.RunID == manifest.RunID &&
			facts.SchemaVersion == artifacts.SchemaVersionRepoFactsV1 && binding.Scope.Hash != "" &&
			facts.Scope == binding.Scope && manifest.Scope == binding.Scope && len(facts.Symbols) > 0 {
			symByID := make(map[artifacts.SymbolID]artifacts.Symbol, len(facts.Symbols))
			for _, sym := range facts.Symbols {
				symByID[sym.SymbolID] = sym
			}
			contextBinding := binding
			contextBinding.RepoFacts = &facts
			appendSymbol := func(header string, sym artifacts.Symbol, maxLines int) {
				bound, err := contracts.BindSubject(artifacts.ContractSubject{
					Path: sym.File, Symbol: sym.Name, SymbolID: sym.SymbolID,
				}, contextBinding)
				if err != nil {
					return
				}
				appendSpan(header, bound.Path, bound.StartLine, min(bound.EndLine, bound.StartLine+maxLines-1))
			}
			subjectIDs := resolveContractSubjectSymbolIDs(c.Subjects, facts.Symbols)
			if len(subjectIDs) == 0 {
				return out.String()
			}
			callerIDs := map[artifacts.SymbolID]bool{}
			calleeIDs := map[artifacts.SymbolID]bool{}
			for _, edge := range facts.CallEdges {
				if subjectIDs[edge.CalleeID] && !subjectIDs[edge.CallerID] {
					callerIDs[edge.CallerID] = true
				}
				if subjectIDs[edge.CallerID] && !subjectIDs[edge.CalleeID] {
					calleeIDs[edge.CalleeID] = true
				}
			}
			added := 0
			// Pass A: direct callers first (establishes reachability/entry preconditions).
			for _, sym := range facts.Symbols {
				if added >= 3 || out.Len() >= maxExtraBytes {
					break
				}
				if sym.File == "" || sym.StartLine <= 0 || subjectIDs[sym.SymbolID] || !callerIDs[sym.SymbolID] {
					continue
				}
				appendSymbol("Direct caller "+sym.Name, sym, 66)
				added++
			}
			// Pass B: direct callees strictly by resolved SymbolID.
			for _, sym := range facts.Symbols {
				if added >= 5 || out.Len() >= maxExtraBytes {
					break
				}
				if sym.File == "" || sym.StartLine <= 0 || subjectIDs[sym.SymbolID] || callerIDs[sym.SymbolID] || !calleeIDs[sym.SymbolID] {
					continue
				}
				appendSymbol("Related callee "+sym.Name, sym, 66)
				added++
			}

			// 3. Exact SymbolID-based struct-field bridge consumers/producers from BoundaryTopology.
			var topo artifacts.BoundaryTopology
			if out.Len() < maxExtraBytes && runfs.ReadJSON(runfs.BoundaryTopologyPath(binding.RunDir), &topo) == nil &&
				topo.SchemaVersion == artifacts.SchemaVersionBoundaryTopologyV1 && topo.RunID == facts.RunID && topo.Scope == facts.Scope {
				bridgeAdded := 0
				seenPartner := map[artifacts.SymbolID]bool{}
				for _, br := range topo.StructFieldBridges {
					if bridgeAdded >= 4 || out.Len() >= maxExtraBytes {
						break
					}
					if strings.HasPrefix(br.Field, "(unnamed ") {
						continue
					}
					isWriter, isAccessor := false, false
					for _, w := range br.DirectWriters {
						if subjectIDs[w] {
							isWriter = true
							break
						}
					}
					if !isWriter {
						for _, a := range br.NonWriteAccessors {
							if subjectIDs[a] {
								isAccessor = true
								break
							}
						}
					}
					if !isWriter && !isAccessor {
						continue
					}
					partners := br.NonWriteAccessors
					roleLabel := "Struct-field consumer"
					if !isWriter {
						partners = br.DirectWriters
						roleLabel = "Struct-field writer"
					}
					for _, pid := range partners {
						if bridgeAdded >= 4 || out.Len() >= maxExtraBytes {
							break
						}
						if seenPartner[pid] || subjectIDs[pid] {
							continue
						}
						sym, ok := symByID[pid]
						if !ok || sym.File == "" || sym.StartLine <= 0 {
							continue
						}
						seenPartner[pid] = true
						appendSymbol(fmt.Sprintf("%s (%s): %s", roleLabel, br.Field, sym.Name), sym, 76)
						bridgeAdded++
					}
				}
			}
		}
	}
	return out.String()
}

// resolveContractSubjectSymbolIDs uses the source-bound identity when present.
// A partial source window may start after its definition's first line; that does
// not justify picking an arbitrary preceding same-name definition or overload.
func resolveContractSubjectSymbolIDs(subjects []artifacts.ContractSubject, symbols []artifacts.Symbol) map[artifacts.SymbolID]bool {
	out := map[artifacts.SymbolID]bool{}
	for _, subject := range subjects {
		sPath := filepath.ToSlash(filepath.Clean(subject.Path))
		if sPath == "." || subject.Symbol == "" {
			continue
		}
		var candidates []artifacts.Symbol
		for _, sym := range symbols {
			if filepath.ToSlash(filepath.Clean(sym.File)) != sPath ||
				(sym.Name != subject.Symbol && sym.QualifiedName != subject.Symbol) || sym.SymbolID == "" || sym.StartLine < 1 {
				continue
			}
			if subject.SymbolID != "" && sym.SymbolID != subject.SymbolID {
				continue
			}
			if subject.EndLine > 0 && sym.StartLine > subject.EndLine {
				continue
			}
			candidates = append(candidates, sym)
		}
		if len(candidates) == 1 {
			out[candidates[0].SymbolID] = true
			continue
		}
		// Without an exact ID, a whole-definition window can disambiguate a
		// single declaration start. Ambiguous partial windows stay unresolved.
		if subject.SymbolID == "" && subject.StartLine > 0 && subject.EndLine >= subject.StartLine {
			var inRange []artifacts.Symbol
			for _, sym := range candidates {
				if sym.StartLine >= subject.StartLine && sym.StartLine <= subject.EndLine {
					inRange = append(inRange, sym)
				}
			}
			if len(inRange) == 1 {
				out[inRange[0].SymbolID] = true
			}
		}
	}
	return out
}

// Additional context is subject to the same root and symlink restrictions as
// contract evidence, even when its path came from an on-disk program index.
func contextSourcePath(root, relative string) (string, error) {
	if root == "" || relative == "" || filepath.IsAbs(relative) || strings.ContainsRune(relative, 0) {
		return "", fmt.Errorf("context requires a relative source path")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("context source escapes repository")
	}
	current, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(current)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("invalid or symlinked context root")
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err = os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("invalid or symlinked context path")
		}
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("context source is not a regular file")
	}
	return current, nil
}
