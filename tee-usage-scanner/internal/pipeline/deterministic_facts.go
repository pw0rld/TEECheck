package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// deterministicCasesFn is the seam runL3Planner invokes for the P4+ lane. It
// defaults to the real implementation; tests in this package swap it to inject
// a canned producer, because driving the real lane needs a CodeQL engine that
// is absent from the test image (deterministicFactCases is a no-op when the
// engine is unavailable). The swap restores via t.Cleanup.
var deterministicCasesFn = deterministicFactCases

// evidenceSnippetsFn is the seam for the evidence-window enrichment: the
// real implementation reads the run's repo facts and slices source; tests
// swap it to avoid needing an index fixture.
var evidenceSnippetsFn = deterministicEvidenceSnippets

// deterministicFactCases is the P4+ automatic deterministic lane: it fires
// the structured fact layer (trustirfacts.Run) once per scan, for every
// operation the layer supports, independent of whether the planner chose to
// call fact_layer_query, and promotes each positive result into a grounded
// CasePack.
//
// Why this exists. The fact layer is the only planner-independent,
// leakage-free detection route: it materializes a repository's fact table,
// runs a thin-shell CodeQL query, and returns grounded locations without ever
// injecting its output into LLM reasoning. Its defect on CVE-2026-44362 was
// not in the lane itself — when invoked it correctly resolved the missing
// rollback propagation to core/crypto/signed_hdr.c (see the
// factLayerQueryOutput.Findings doc comment in internal/planner/actions) — but
// in its trigger: the only way the lane could fire was a planner model
// choosing fact_layer_query unprompted, which across four runs on that CVE
// happened once (see trustirfacts.request.go's tweOperations doc comment).
// Firing the lane here removes that dependence on model behaviour, which is
// the single highest-leverage, leakage-free fix on the CVE-catching roadmap.
//
// No-op, not error, when there is nothing deterministic to say — but only for
// the statuses that genuinely mean "no case". CodeQL absent (eng.Available()
// false) returns early; a repository with no fact table, an unimplemented
// operation, or an empty table returns StatusUnsupported, and an unavailable
// engine/database or a failed analyze returns StatusUnresolved — both are
// dropped here, never fabricating a case (matching Run's own "never fake an
// empty success" contract). A genuine zero-location success (the fixed
// revision) is dropped too. StatusError is different: it is the fact layer's
// OWN plumbing failure (it could not write or read back its generated query
// pack — run.go's errorFact), returned with a nil Go error, and is surfaced
// here as a non-nil error rather than swallowed. A malformed request or
// schema-validation failure is surfaced the same way.
//
// The returned packs are appended to the planner's allPacks BEFORE
// planner.DedupePacks runs (see runL3Planner), so a deterministic pack that
// lands on the same file as a planner lead merges with it losslessly — absorb
// unions ToolFactRefs — rather than occupying a second --max-cases slot.
func deterministicFactCases(ctx context.Context, eng trustirfacts.Engine, db codedb.DatabaseProvider, queryPackDir, runDir, repoRoot, repoURL, commit, focus string) ([]artifacts.CasePack, error) {
	if eng == nil || !eng.Available() {
		// Mirrors FactLayerQueryHandler's fail-closed stance: no engine means
		// the lane is inert for this run, never a fabricated clean bill.
		return nil, nil
	}
	var packs []artifacts.CasePack
	var funcIndex map[string][]functionDef
	for _, op := range trustirfacts.SupportedOperations() {
		fact, factPath, err := trustirfacts.RunAndPersist(ctx, eng, db, trustirfacts.Request{
			RunDir:       runDir,
			Repository:   repoURL,
			Commit:       commit,
			Operation:    op,
			QueryPackDir: queryPackDir,
		})
		if err != nil {
			return nil, fmt.Errorf("deterministic fact lane %s: %w", op, err)
		}
		if fact.Status == trustirfacts.StatusError {
			// StatusError is the fact layer's OWN plumbing failure (run.go's
			// errorFact, e.g. it could not materialize or read back its own
			// generated query pack), returned with a nil Go error. That is a
			// bug in the lane, not a statement about the target repository —
			// surface it instead of swallowing it alongside an unsupported
			// repository.
			return nil, fmt.Errorf("deterministic fact lane %s: internal fact-layer failure: %s", op, fact.Error)
		}
		if fact.Status != trustirfacts.StatusSuccess || len(fact.Locations) == 0 {
			// unsupported (no table / op not implemented) or unresolved
			// (engine/db/analyze), or a genuine zero-location success (the
			// fixed revision): all are "no case to promote", never a faked
			// clean bill.
			continue
		}
		// Evidence window: the pack's structural anchor is complete, but the
		// downstream chain judges IMPACT from what it can see. Attach the
		// definitions (producer, authority, produced + referenced structs)
		// so the arbiter's confidence reflects the evidence actually
		// available, not a window that happened to miss the authority's body
		// (see evidence_window.go). The function index (~32 MB on OP-TEE)
		// loads once per lane pass, not per positive fact.
		var tablePtr *trustirfacts.FactTable
		if table, ok := trustirfacts.FactTableFor(repoURL); ok {
			tablePtr = &table
		}
		if funcIndex == nil {
			funcIndex = loadFunctionIndex(runDir)
			if funcIndex == nil {
				funcIndex = map[string][]functionDef{}
			}
		}
		snippets := evidenceSnippetsFn(repoRoot, funcIndex, fact, tablePtr)
		pack := factCasePack(fact, factPath, op, focus, snippets)
		pack = bindDeterministicContracts(pack, fact, factPath, tablePtr, runDir, repoRoot, repoURL, commit)
		packs = append(packs, pack)
	}
	return packs, nil
}

// factCasePack turns one positive fact-layer result into a grounded CasePack.
//
// The persisted ToolFact travels BY REFERENCE (ToolFactRefs), not by value:
// downstream Expert/Challenger/Verifier/Arbiter resolve the real,
// schema-validated evidence at that path (artifacts.FormatToolFact) rather
// than re-deriving it from a copy that could drift. TargetFiles come from the
// finding's own locations so planner.DedupePacks treats the pack as a real
// review unit (a pack with no target files is dropped — see
// casepacks.goMerge) and can merge it with any planner case on the same file.
// TargetSymbols are recovered from the finding's named (related) sites — the
// primary location carries no symbol by design (run.go's toolLocations).
func factCasePack(fact artifacts.ToolFact, factPath string, op trustirfacts.Operation, focus string, snippets []artifacts.PromptSnippet) artifacts.CasePack {
	seen := map[string]bool{}
	targetFiles := make([]string, 0, len(fact.Locations))
	for _, loc := range fact.Locations {
		if loc.Path != "" && !seen[loc.Path] {
			seen[loc.Path] = true
			targetFiles = append(targetFiles, loc.Path)
		}
	}
	var symbols []string
	for _, f := range fact.Findings {
		for _, rel := range f.Related {
			if rel.Symbol != "" {
				symbols = append(symbols, rel.Symbol)
			}
		}
	}
	// WhySelected prefers the query's own conclusion (its finding message),
	// which states precisely what the structural gap is and names the sites;
	// only falls back to a generic provenance line when the query emitted
	// locations without a message.
	why := fmt.Sprintf("deterministic fact layer (%s) reported a structural positive; planner-independent, tool-grounded evidence at %s", op, factPath)
	if len(fact.Findings) > 0 && fact.Findings[0].Message != "" {
		why = fact.Findings[0].Message
	}
	var twe []string
	if id, ok := trustirfacts.TWEForOperation(op); ok {
		twe = []string{id}
	}
	// The fact-layer query proves a structural gap — a producer that does not
	// propagate the rollback-relevant field plus a configured authority that
	// reads it — NOT an attacker-to-authority exploit path (see
	// RollbackVersionNotPropagated.ql). The arbiter's attackChainComplete
	// (internal/arbiter/chain.go) treats an empty MissingLinks as satisfied,
	// which would let this flow-empty pack be labeled confirmed_candidate
	// purely from structural evidence. Naming the untraced producer→authority
	// dataflow here makes the gate return false, so the finding is labeled
	// likely_issue — still surfaced, still pinpointing the site, CodeQL-grounded
	// — rather than overclaimed as a complete attack chain. No downstream stage
	// clears pack.MissingLinks, so the label is deterministic (independent of
	// the stochastic verifier outcome), which is the honest ceiling for a lane
	// whose evidence is structural by construction. This mirrors the
	// planner-led path's missingLinks (investigations/casepack.go), which
	// states the investigation's outstanding next-tasks; here the outstanding
	// task is the dataflow the structural query deliberately does not trace.
	missingLinks, coverageGaps, requiredEvidence := structuralEvidentialFields(fact, op)
	return artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        "deterministic:" + fact.FactID,
		Focus:         focus,
		// state_machine is the categoryForKind bucket that already covers the
		// rollback/state family (internal/planner/casepacks.go), so downstream
		// case templating treats this like a planner state-machine lead.
		Category:         "state_machine",
		Priority:         "high",
		TargetFiles:      targetFiles,
		TargetSymbols:    symbols,
		WhySelected:      []string{why},
		ToolFactRefs:     []string{factPath},
		RelatedTWEs:      twe,
		MissingLinks:     missingLinks,
		RequiredEvidence: requiredEvidence,
		CoverageGaps:     coverageGaps,
		// Snippets carry the evidence window: definition bodies of the
		// finding's producer/authority plus produced-struct definitions.
		// Enrich (internal/cases) MERGES its generic snippets with these
		// rather than overwriting, so the definitions survive delivery.
		Snippets: snippets,
	}
}

// producerAuthoritySymbols extracts the (producer, authority) symbol pair a
// rollback-propagation finding names, in document order, from the finding's
// related sites. The query emits the missing-write site as the first related
// entry and an authority that reads the field as a later one (see the finding
// message format in internal/trustirfacts/run.go). ok is false when fewer than
// two distinct symbols are present, in which case the caller falls back to a
// site-agnostic statement. Derived from the fact's own output, not hardcoded,
// so it generalizes to any repository the lane runs against.
func producerAuthoritySymbols(fact artifacts.ToolFact) (producer, authority string, ok bool) {
	var first string
	for _, f := range fact.Findings {
		for _, rel := range f.Related {
			s := strings.TrimSpace(rel.Symbol)
			if s == "" {
				continue
			}
			if first == "" {
				first = s
			} else if s != first {
				return first, s, true
			}
		}
	}
	return "", "", false
}

// structuralEvidentialFields returns the three evidential fields a
// deterministic CasePack must carry so its structural-only evidence is never
// mistaken for a complete attack chain: MissingLinks (the gate's mechanical
// input — the untraced producer→authority dataflow), RequiredEvidence (what
// would resolve that link), and CoverageGaps (the known scope limitation).
func structuralEvidentialFields(fact artifacts.ToolFact, op trustirfacts.Operation) (missingLinks, coverageGaps, requiredEvidence []string) {
	producer, authority, ok := producerAuthoritySymbols(fact)
	var link string
	if ok {
		link = fmt.Sprintf("runtime dataflow from %s (producer; rollback-relevant field not propagated) to %s (authority) is not mechanically traced by %s — structural detection only", producer, authority, op)
	} else {
		link = fmt.Sprintf("runtime producer→authority dataflow is not mechanically traced by %s — structural detection only", op)
	}
	return []string{link},
		[]string{fmt.Sprintf("%s establishes a missing field write and a configured authority, not an attacker-to-authority exploit path; exploitability is for the downstream investigation to confirm", op)},
		[]string{"a traced or runtime-demonstrated producer→authority dataflow showing the unpropagated field reaches the authority under attacker control"}
}

// capPreservingGrounded applies the --max-cases cap after dedupe while ensuring
// a tool-grounded pack (one carrying a resolvable ToolFactRef) is never
// truncated to make room for an ungrounded planner lead.
//
// A CodeQL-confirmed case is the highest-confidence output of the run —
// structural evidence the fact layer reproduced, not a planner hypothesis — so
// dropping it for a hypothesis would invert the confidence ordering the
// deterministic lane exists to provide. Grounded packs therefore take the
// first slots; the remaining budget is filled by ungrounded packs in their
// existing (dedupe-imposed) order.
//
// The one case a grounded pack CAN be truncated is when grounded packs alone
// exceed the cap: --max-cases is a hard ceiling, so N grounded packs in a
// budget of M<N must lose N-M of their number. That cannot happen today (one
// supported operation ⇒ at most one grounded pack), and when it does the loss
// falls on the trailing grounded packs. max <= 0 means "no cap" (mirrors
// runL3Planner's existing cfg.MaxCases == 0 guard).
func capPreservingGrounded(packs []artifacts.CasePack, max int) []artifacts.CasePack {
	if max <= 0 || len(packs) <= max {
		return packs
	}
	grounded := make([]artifacts.CasePack, 0)
	rest := make([]artifacts.CasePack, 0)
	for _, p := range packs {
		if len(p.ToolFactRefs) > 0 {
			grounded = append(grounded, p)
		} else {
			rest = append(rest, p)
		}
	}
	if len(grounded) >= max {
		return grounded[:max]
	}
	out := make([]artifacts.CasePack, 0, max)
	out = append(out, grounded...)
	out = append(out, rest[:max-len(grounded)]...)
	return out
}
