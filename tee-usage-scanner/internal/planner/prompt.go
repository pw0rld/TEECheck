package planner

import (
	"fmt"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// PromptProfile is the repository identity and caller intent the planner
// injects into the round prompt.
type PromptProfile struct {
	RepoURL string
	Commit  string
	Focus   string
	// Hint is the caller's free-text concern. Optional; empty renders nothing.
	Hint      string
	FileCount int
}

// PriorKnowledge is everything from the project-understanding and TWE
// layers the Planner injects into its system prompt (§7.5): the full
// compiled TWE catalog text, a compact rendering of the Architecture
// Model, and the current Project Invariants. Each field is independently
// optional — a zero-value PriorKnowledge renders no extra sections, so a
// caller that has not wired this context yet (e.g. internal/pipeline's
// legacy Rust-focused L3 run) keeps working unchanged.
type PriorKnowledge struct {
	// TWEText is twecontext.Catalog.Compile().Text — the complete,
	// agent-ready TWE prior-knowledge context. Injected verbatim (§11.1:
	// compiled once, shared read-only by every agent). This package does
	// not import internal/twecontext itself — the caller compiles once
	// and passes the resulting text, keeping the planner decoupled from
	// playbook YAML loading.
	TWEText string

	// Architecture is the full run's ArchitectureModel. BuildSystemPrompt
	// renders a compact one-line-per-element/relation slice (id, kind,
	// name/from/to — not full evidence) rather than the entire dossier,
	// keeping prompt size bounded per §11.3.
	Architecture *artifacts.ArchitectureModel

	// Invariants is the current run's Project Invariants (status
	// "proposed" — see §7.4). Rendered as statement + related TWEs +
	// verification plan so the Planner can turn each into concrete
	// investigation tasks (§7.5).
	Invariants []artifacts.ProjectInvariant
}

// actionArgSchemas documents the exact args shape each action
// expects. Used by BuildSystemPrompt so the LLM does not guess at
// parameter names — guessing leads to silent failures like the LLM
// passing include_patterns when the ripgrep handler wants globs.
//
// Keep entries terse (one line each). When a new action is added
// to the registry, add a matching entry here.
var actionArgSchemas = map[string]string{
	"get_repository_card": `{}` + ` — what the project says it is, how it builds, how many files and modules it has, and what the program index can and cannot answer. Start here`,
	"list_modules":        `{}` + ` — every module with its file and function counts and its dependency edges. The counts are how you tell the project's own code from vendored dependencies`,
	"list_functions":      `{"module": string (a path from list_modules), "page": int (0-based)}` + ` — one page of function cards. The reply names the next cursor; a module absent from the index is not a module without functions`,
	"find_symbols":        `{"name": string (a function name), "page": int (0-based, optional)}` + ` — every indexed definition carrying that name, with its symbol_id. More than one is normal: two files can each define a static function of the same name, and choosing between them is yours to do, by id`,
	"get_function_card":   `{"symbol_id": string (from find_symbols or list_functions)}` + ` — one definition's callers, callees and the struct fields it touches and writes, each with the scope of what that check can prove`,
	"get_callers":         `{"symbol_id": string}` + ` — the resolved callers of one definition, together with the repository-wide counts of call sites this list cannot cover. An absent caller is not proof of unreachability`,
	"list_dir":            `{"path": string (repo-relative), "depth": int (0-3)}`,
	"read_file":           `{"path": string (repo-relative), "start": int (1-indexed), "end": int (1-indexed, 0 for cap)}`,
	"ripgrep":             `{"pattern": string (regex), "globs": [string]} — these are the ONLY two arguments and any other is rejected. globs may be path-qualified relative to the repo root ("core/crypto/*.c") or bare ("*.c","*.h"). For a case-insensitive search put the flag in the pattern itself, e.g. "(?i)<pattern>". Zero matches is reported as "(no matches)", which means the search ran and found nothing — it is not evidence that the thing does not exist elsewhere`,
	"tree_sitter_outline": `{"path": string (a source file: .c/.h/.rs/...)}`,
	"reverse_trace":       `{"file": string (a source file where the symbol is defined), "symbol": string (function name), "depth": int (1-3, default 1)} — walks backward through source files, returns a tree of who calls the symbol and who calls THOSE callers up to depth levels; use this to ask "who calls X?" in one step instead of running many ripgreps`,
	"repomix_summarize":   `{"path": string (repo-relative), "compress": bool (optional)}`,
	"twe_playbook_detail": `{"twe_id": string (e.g. "TWE-STATE-001")} — returns the FULL investigation method for one TWE: attacker capabilities, investigation steps, required evidence, common defenses, and common false positives. Your system prompt carries only the brief tier; pull the detail for any TWE you are actually investigating`,
	"done":                `{"summary": string, "candidates": [{"id": string, "kind": string, "priority": "high"|"medium"|"low", "paths": [string], "symbols": [string], "why_selected": [string], "sink_category": string, "confidence": float (0.0-1.0)}], "investigations": [{"twe_ids": [string], "invariant_ids": [string], "architecture_refs": [string], "classification": "standard"|"variant" (only meaningful with exactly one twe_id — see APPROACH), "filled_roles": {"<role>": {"path": string, "start_line": int, "symbol": string}}, "missing_roles": [string], "required_evidence": [string], "counterevidence": [string], "coverage_gaps": [string], "tool_fact_refs": [string]}] (optional)}`,
}

// BuildSystemPrompt returns the static system prompt the planner
// sends with every LLM request. It explains the agent role, lists
// available actions with typed arg schemas, optionally inlines the
// curated obligations wiki and TWE/Architecture/Invariant prior
// knowledge, and specifies the JSON response format.
//
// obligationsBlock should be the string returned by LoadObligations.
// Pass "" to skip the obligations section entirely. knowledge is §7.5's
// prior-knowledge injection (TWE catalog, Architecture slice, Project
// Invariants) — pass PriorKnowledge{} to skip all three sections.
func BuildSystemPrompt(availableActions []string, obligationsBlock string, knowledge PriorKnowledge) string {
	var b strings.Builder
	b.WriteString("You are TEECheck's L3 security audit planner (Investigator, §7.5). Your job is to drive TWE-guided investigations of a TEE codebase using its Architecture Model and Project Invariants, calling the structured fact layer for real evidence, and to record what you found as bounded, source-anchored investigations — not to render a final vulnerability verdict.\n\n")

	b.WriteString("CRITICAL RULES:\n")
	b.WriteString("  - A missing role in an investigation (missing_roles) is YOUR NEXT INVESTIGATIVE TASK. It is NOT a vulnerability conclusion, and it is NOT evidence of safety. Keep investigating until you either fill the role, exhaust your budget, or have concrete evidence it does not exist in this codebase.\n")
	b.WriteString("  - A fact_layer_query that returns status \"unresolved\" or \"unsupported\", or a query with zero locations, does NOT mean \"no vulnerability\" or \"safe\". It only proves no match was found within the modeled scope (§6.5). Never conclude safety from an absence of a match.\n")
	b.WriteString("  - You do not decide the final vulnerability verdict. Report what you found (filled/missing roles, required evidence, counterevidence, coverage gaps) — Expert/Challenger/Verifier judge it afterward.\n\n")

	if strings.TrimSpace(knowledge.TWEText) != "" {
		b.WriteString("=== TWE PRIOR KNOWLEDGE (complete catalog; use it to decide what to investigate) ===\n")
		b.WriteString(knowledge.TWEText)
		b.WriteString("\n\n")
	}

	if knowledge.Architecture != nil {
		if slice := renderArchitectureSlice(*knowledge.Architecture); slice != "" {
			b.WriteString("=== ARCHITECTURE MODEL (project-specific; from the Architecture Agent) ===\n")
			b.WriteString(slice)
			b.WriteString("\n")
		}
	}

	if len(knowledge.Invariants) > 0 {
		b.WriteString("=== PROJECT INVARIANTS (status=proposed — obligations to verify, not findings) ===\n")
		b.WriteString(renderInvariants(knowledge.Invariants))
		b.WriteString("\n")
	}

	if strings.TrimSpace(obligationsBlock) != "" {
		b.WriteString("SECURITY OBLIGATIONS TO KEEP IN MIND (curated wiki, treat these as the review criteria a downstream human auditor will apply):\n")
		b.WriteString(obligationsBlock)
		b.WriteString("\n\n")
	}

	b.WriteString("AVAILABLE ACTIONS (use the EXACT arg names shown — wrong names are silently ignored):\n")
	for _, name := range availableActions {
		schema, ok := actionArgSchemas[name]
		if name == "fact_layer_query" {
			schema = factLayerQuerySchema()
			ok = true
		}
		if !ok {
			schema = "{...}"
		}
		fmt.Fprintf(&b, "  - %s  args=%s\n", name, schema)
	}
	b.WriteString("\n")

	b.WriteString("APPROACH:\n")
	b.WriteString("  1. Start from the Project Invariants and TWE prior knowledge above: pick a security obligation this component must uphold.\n")
	b.WriteString("  2. When a TWE from the prior knowledge looks relevant to this code, call twe_playbook_detail with its id to get the full investigation method before you start searching.\n")
	b.WriteString("  3. Use ripgrep (with globs matching the project's source languages — see the `languages:` line in the round prompt) to find concrete sites related to that obligation.\n")
	b.WriteString("  4. Use tree_sitter_outline on a relevant source file to get its structure before reading specific ranges with read_file.\n")
	b.WriteString("  5. Use reverse_trace to walk backward from a trust-decision point to its callers.\n")
	b.WriteString("  6. When you have evidence, call done with candidates and, where a TWE/invariant applies, an investigations entry.\n\n")

	b.WriteString("HINTS:\n")
	b.WriteString("  - Match ripgrep globs to the target's source languages; skip lockfiles, build manifests, and docs.\n")
	b.WriteString("  - Prioritize directories that cross the trust boundary (TA entry points, secure-world core, attestation, key handling).\n")
	b.WriteString("  - You MUST call done by round 7 at the latest. Budget is 8 rounds total.\n\n")

	b.WriteString("RESPONSE FORMAT (strict JSON, no extra text, no markdown code fences):\n")
	b.WriteString(`{
  "thought": "<your reasoning for this round, 1-3 sentences>",
  "actions": [
    {"name": "<action_name>", "args": {<typed args object matching the schema above>}}
  ]
}
`)
	b.WriteString("\nDo not call more than 3 actions per round. Do not repeat the same (action, args) tuple more than twice in a row — the planner will reject it.\n")
	return b.String()
}

// maxArchitectureElementsRendered bounds how many Architecture Model
// elements/relations BuildSystemPrompt renders — a compact per-item summary
// line, not the full evidence-bearing model (§11.3). A project with a large
// model still gets a usable prompt instead of an unbounded one.
const maxArchitectureElementsRendered = 60

// renderArchitectureSlice renders a compact, one-line-per-item summary of
// model: id, kind, name (for elements) or from/to (for relations). It never
// includes Evidence — that stays in the persisted ArchitectureModel
// artifact, referenced by ID, per §11.3.
func renderArchitectureSlice(model artifacts.ArchitectureModel) string {
	var lines []string
	addElements := func(bucket string, elems []artifacts.ArchitectureElement) {
		for _, el := range elems {
			lines = append(lines, fmt.Sprintf("- [%s] %s (%s) %q state=%s", bucket, el.ID, el.Kind, el.Name, el.State))
		}
	}
	addRelations := func(bucket string, rels []artifacts.ArchitectureRelation) {
		for _, rel := range rels {
			lines = append(lines, fmt.Sprintf("- [%s] %s (%s) %s -> %s state=%s", bucket, rel.ID, rel.Kind, rel.From, rel.To, rel.State))
		}
	}
	addElements("party", model.Parties)
	addElements("component", model.Components)
	addElements("role", model.Roles)
	addElements("asset", model.Assets)
	addElements("trust_zone", model.TrustZones)
	addElements("entrypoint", model.Entrypoints)
	addRelations("boundary", model.Boundaries)
	addRelations("data_flow", model.DataFlows)
	addRelations("state_lifecycle", model.StateLifecycles)
	addElements("trust_assumption", model.TrustAssumptions)
	addElements("deployment_assumption", model.DeploymentAssumptions)
	addElements("unknown", model.Unknowns)

	if len(lines) == 0 {
		return ""
	}
	total := len(lines)
	truncated := total > maxArchitectureElementsRendered
	if truncated {
		lines = lines[:maxArchitectureElementsRendered]
	}
	out := strings.Join(lines, "\n") + "\n"
	if truncated {
		out += fmt.Sprintf("... (truncated to %d of %d elements; the full model is in the run's architecture.v1.json artifact)\n", maxArchitectureElementsRendered, total)
	}
	return out
}

// maxInvariantsRendered bounds how many Project Invariants
// BuildSystemPrompt renders, for the same reason as
// maxArchitectureElementsRendered.
const maxInvariantsRendered = 30

func renderInvariants(invs []artifacts.ProjectInvariant) string {
	var b strings.Builder
	n := len(invs)
	truncated := n > maxInvariantsRendered
	if truncated {
		n = maxInvariantsRendered
	}
	for _, inv := range invs[:n] {
		fmt.Fprintf(&b, "- %s: %s\n", inv.InvariantID, inv.Statement)
		if len(inv.RelatedTWEs) > 0 {
			fmt.Fprintf(&b, "  related_twes: %s\n", strings.Join(inv.RelatedTWEs, ", "))
		}
		if len(inv.VerificationPlan) > 0 {
			fmt.Fprintf(&b, "  verification_plan: %s\n", strings.Join(inv.VerificationPlan, "; "))
		}
	}
	if truncated {
		fmt.Fprintf(&b, "... (truncated to %d of %d invariants; the full set is in the run's project_invariants.v1.json artifact)\n", maxInvariantsRendered, len(invs))
	}
	return b.String()
}

// BuildRoundPrompt assembles the user-message prompt for a single
// planner round. It includes the project profile, accumulated
// candidates, the trailing window of recent observations, and the
// remaining budget.
// scrollbackBytes bounds an observation from a round that is no longer the
// most recent one.
//
// It is deliberately NOT observationlimits.MaxBytes, and it is the only
// place a second number is legitimate. The newest round's observations are
// what the model is reasoning about now and arrive whole, at the budget the
// action built them to; the round before it is context, and rendering two
// full 32 KiB pages every round would cost more prompt than the reasoning
// they support.
//
// The distinction matters because the failure it replaces was the opposite:
// every observation was cut to 1500 bytes with a bare "(truncated)" marker,
// so a page built to a 32 KiB budget reached the model as 1500 bytes with
// nothing to say the rest existed. Here the marker says which round it is
// from, how much was dropped, and how to get it back.
const scrollbackBytes = 1500

func BuildRoundPrompt(state *PlannerState, profile PromptProfile, budget Budget, avoidPaths []string) string {
	var b strings.Builder

	if len(avoidPaths) > 0 {
		b.WriteString("=== ALREADY COVERED BY PREVIOUS PASSES (must avoid) ===\n")
		b.WriteString("The following file::symbol targets were already audited in earlier passes\n")
		b.WriteString("of this audit session. Your job THIS pass is to find DIFFERENT code paths\n")
		b.WriteString("that were NOT touched before. Do not re-pick these exact targets.\n")
		b.WriteString("If the repo has no remaining TEE-relevant code paths to audit, call done\n")
		b.WriteString("with an empty candidates list and explain in the summary.\n\n")
		for _, p := range avoidPaths {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
		b.WriteString("\n")
	}

	b.WriteString("=== PROJECT ===\n")
	if profile.RepoURL != "" {
		fmt.Fprintf(&b, "repo: %s\n", profile.RepoURL)
	}
	if profile.Commit != "" {
		fmt.Fprintf(&b, "commit: %s\n", profile.Commit)
	}
	if profile.Focus != "" {
		fmt.Fprintf(&b, "focus: %s\n", profile.Focus)
	}
	if profile.Hint != "" {
		// The caller's own concern, verbatim. It orders the work; it does not
		// settle it. A reviewer who says "I suspect the TA loading path" is
		// reporting a suspicion, not evidence, and a run that returns the
		// suspicion restated is worth nothing — so the instruction is to
		// investigate it first and to say plainly when it does not hold up.
		fmt.Fprintf(&b, "\ncaller's stated concern (investigate this first; it is a"+
			" priority, NOT a finding — report honestly if the evidence does not"+
			" support it, and keep investigating anything else the evidence points"+
			" to):\n%s\n\n", profile.Hint)
	}
	if profile.FileCount > 0 {
		fmt.Fprintf(&b, "files: %d\n", profile.FileCount)
	}
	b.WriteString("\n")

	b.WriteString("=== BUDGET ===\n")
	fmt.Fprintf(&b, "rounds: %d/%d\n", budget.RoundsUsed, budget.MaxRounds)
	fmt.Fprintf(&b, "tokens: %d/%d\n", budget.TokensUsed, budget.MaxTokens)
	b.WriteString("\n")

	if len(state.Candidates) > 0 {
		b.WriteString("=== CANDIDATES SO FAR ===\n")
		for _, c := range state.Candidates {
			fmt.Fprintf(&b, "- %s [%s, %s]\n", c.ID, c.Kind, c.Priority)
			if len(c.Paths) > 0 {
				fmt.Fprintf(&b, "  paths: %s\n", strings.Join(c.Paths, ", "))
			}
			if len(c.Symbols) > 0 {
				fmt.Fprintf(&b, "  symbols: %s\n", strings.Join(c.Symbols, ", "))
			}
		}
		b.WriteString("\n")
	}

	if len(state.Investigations) > 0 {
		b.WriteString("=== ACTIVE TWE INVESTIGATIONS ===\n")
		for _, inv := range state.Investigations {
			fmt.Fprintf(&b, "- %s [%s] classification=%s\n", inv.InvestigationID, strings.Join(inv.TWEIDs, ","), inv.Classification)
			if len(inv.FilledRoles) > 0 {
				roleNames := make([]string, 0, len(inv.FilledRoles))
				for role := range inv.FilledRoles {
					roleNames = append(roleNames, role)
				}
				sort.Strings(roleNames)
				var parts []string
				for _, role := range roleNames {
					loc := inv.FilledRoles[role]
					parts = append(parts, fmt.Sprintf("%s=%s:%d", role, loc.Path, loc.StartLine))
				}
				fmt.Fprintf(&b, "  filled_roles: %s\n", strings.Join(parts, ", "))
			}
			if len(inv.MissingRoles) > 0 {
				fmt.Fprintf(&b, "  MISSING ROLES (your NEXT investigative task, NOT a vulnerability conclusion): %s\n", strings.Join(inv.MissingRoles, ", "))
			}
			if len(inv.RequiredEvidence) > 0 {
				fmt.Fprintf(&b, "  outstanding required evidence: %s\n", strings.Join(inv.RequiredEvidence, "; "))
			}
			if len(inv.CounterEvidence) > 0 {
				fmt.Fprintf(&b, "  counterevidence observed: %s\n", strings.Join(inv.CounterEvidence, "; "))
			}
			if len(inv.CoverageGaps) > 0 {
				fmt.Fprintf(&b, "  coverage gaps: %s\n", strings.Join(inv.CoverageGaps, "; "))
			}
		}
		b.WriteString("\n")
	}

	if len(state.PlaybookDetails) > 0 {
		b.WriteString("=== TWE PLAYBOOK DETAIL (pulled this run; authoritative investigation method) ===\n")
		for _, d := range state.PlaybookDetails {
			fmt.Fprintf(&b, "--- %s ---\n", d.TWEID)
			b.WriteString(d.Text)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	recent := state.LastRoundsForPrompt(2)
	if len(recent) > 0 {
		b.WriteString("=== RECENT ROUNDS ===\n")
		for i, r := range recent {
			newest := i == len(recent)-1
			fmt.Fprintf(&b, "round %d:\n", r.Round)
			if r.Thought != "" {
				fmt.Fprintf(&b, "  thought: %s\n", r.Thought)
			}
			for _, obs := range r.Observations {
				// The ref is what a lead cites. It has to be in the text
				// the model reads or reason_fact_refs can only be
				// invented.
				id := ""
				if obs.Ref != "" {
					id = "  ref=" + obs.Ref
				}
				if obs.OK {
					fmt.Fprintf(&b, "  [%s] OK%s\n", obs.Name, id)
				} else {
					fmt.Fprintf(&b, "  [%s] ERROR: %s%s\n", obs.Name, obs.Error, id)
				}
				if obs.Output == "" {
					continue
				}
				body := obs.Output
				if !newest && len(body) > scrollbackBytes {
					body = body[:scrollbackBytes] +
						fmt.Sprintf("\n... (scrollback: %d of %d bytes; re-run this action to see the rest)",
							scrollbackBytes, len(obs.Output))
				}
				fmt.Fprintf(&b, "    %s\n", strings.ReplaceAll(body, "\n", "\n    "))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("=== NEXT ===\n")
	b.WriteString("What is your next action? Reply with strict JSON in the format from the system prompt.\n")
	return b.String()
}

// factLayerQuerySchema renders fact_layer_query's arg schema with the
// operations the fact layer can actually execute, enumerated.
//
// The static schema this replaced carried one "e.g." value and no list. A
// model had no way to learn the closed vocabulary, and it failed in both
// available directions: on 2026-07-27 it invented an operation that does
// not exist, and across three runs on 2026-07-29 — including one whose
// repository DID have a fact table, with CodeQL installed and the action
// registered — it never called the action at all, never once mentioning
// the fact layer in eight rounds of reasoning. Every other action takes
// arguments a model can derive from the code in front of it; this one
// alone required a value only the source knew.
func factLayerQuerySchema() string {
	ops := trustirfacts.SupportedOperationStrings()
	list := "(none — the fact layer has no executable operations in this build)"
	if len(ops) > 0 {
		list = strings.Join(ops, " | ")
	}
	return fmt.Sprintf(
		`{"operation": string, one of: %s} — calls the structured CodeQL/TrustIR `+
			`fact layer for one operation against the pinned repository+commit; returns a `+
			`compact observation (tool_fact_ref, status, locations, coverage_gaps). Any other `+
			`value is rejected. Status "unresolved" or "unsupported" is a real answer, not a `+
			`Go error, and must never be read as "no vulnerability" (§6.5)`, list)
}
