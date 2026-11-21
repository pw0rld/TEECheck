package planner

import (
	"fmt"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
	"sort"
	"strings"
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

// PriorKnowledge is the TWE catalog the Planner is shown once it is
// investigating a lead of its own.
//
// It used to also carry the run's Architecture Model and Project
// Invariants. Both are gone, from both passes. A real run traced what they
// did: a keyword match became a freshness candidate, became an
// architecture asset, became an invariant anchored at a line nobody had
// read — and the Planner, handed that invariant at the top of its prompt,
// spent its rounds verifying it instead of reading the project. The
// artifacts still exist and the Expert, Challenger and Verifier still read
// them; they no longer decide what the Planner looks at.
//
// The zero value renders no sections, which is what reconnaissance passes.
type PriorKnowledge struct {
	// TWEText is twecontext.Catalog.Compile().Text — the complete,
	// agent-ready TWE prior-knowledge context. Injected verbatim (§11.1:
	// compiled once, shared read-only by every agent). This package does
	// not import internal/twecontext itself — the caller compiles once
	// and passes the resulting text, keeping the planner decoupled from
	// playbook YAML loading.
	//
	// It is shown in the investigation phase only. In reconnaissance the
	// catalog at the top of the prompt is precisely what makes a Planner
	// go looking for the catalog's vulnerabilities rather than at this
	// project's code — on run-b its first two actions were
	// twe_playbook_detail calls, before it had opened a single file.
	TWEText string
}

// actionArgSchemas documents the exact args shape each action
// expects. Used by BuildSystemPrompt so the LLM does not guess at
// parameter names — guessing leads to silent failures like the LLM
// passing include_patterns when the ripgrep handler wants globs.
//
// Keep entries terse (one line each). When a new action is added
// to the registry, add a matching entry here.
var actionArgSchemas = map[string]string{
	"get_repository_card":   `{}` + ` — what the project says it is, how it builds, how many files and modules it has, and what the program index can and cannot answer. Start here`,
	"list_modules":          `{}` + ` — every module with its file and function counts and its dependency edges. The counts are how you tell the project's own code from vendored dependencies`,
	"list_functions":        `{"module": string (a path from list_modules), "page": int (0-based)}` + ` — one page of function cards. The reply names the next cursor; a module absent from the index is not a module without functions`,
	"find_symbols":          `{"name": string (a function name), "page": int (0-based, optional)}` + ` — every indexed definition carrying that name, with its symbol_id. More than one is normal: two files can each define a static function of the same name, and choosing between them is yours to do, by id`,
	"get_function_card":     `{"symbol_id": string (from find_symbols or list_functions)}` + ` — one definition's callers, callees and the struct fields it touches and writes, each with the scope of what that check can prove`,
	"get_callers":           `{"symbol_id": string}` + ` — the resolved callers of one definition, together with the repository-wide counts of call sites this list cannot cover. An absent caller is not proof of unreachability`,
	"list_dir":              `{"path": string (repo-relative), "depth": int (0-3)}`,
	"read_file":             `{"path": string (repo-relative), "start": int (1-indexed), "end": int (1-indexed, 0 for cap)}`,
	"ripgrep":               `{"pattern": string (regex), "globs": [string]} — these are the ONLY two arguments and any other is rejected. globs may be path-qualified relative to the repo root ("core/crypto/*.c") or bare ("*.c","*.h"). For a case-insensitive search put the flag in the pattern itself, e.g. "(?i)<pattern>". Zero matches is reported as "(no matches)", which means the search ran and found nothing — it is not evidence that the thing does not exist elsewhere`,
	"tree_sitter_outline":   `{"path": string (a source file: .c/.h/.rs/...)}`,
	"reverse_trace":         `{"file": string (a source file where the symbol is defined), "symbol": string (function name), "depth": int (1-3, default 1)} — walks backward through source files, returns a tree of who calls the symbol and who calls THOSE callers up to depth levels; use this to ask "who calls X?" in one step instead of running many ripgreps`,
	"repomix_summarize":     `{"path": string (repo-relative), "compress": bool (optional)}`,
	"open_audit_lead":       `{"security_question": string, "target_symbol_ids": [string (symbol_ids you observed; in tree_only mode a successfully read path or path::symbol is accepted)], "reason": [string], "reason_fact_refs": [string (the ref=obs:... printed beside each observation that showed it)], "requested_context": [string (optional, e.g. "body:f", "callers:f", "def-use:a.x->b.y")], "uncertainty": "low"|"medium"|"high", "related_twes": [string (optional — leave it out; a question no catalog names is not a lesser question)]}` + ` — raise a question about this project's own code. Every target must be a definition you opened, and every reason must cite an observation ref, or the lead is refused`,
	ActionUpdateLead:        `{"lead_id": string, "add_notes": [{"fact_ref": string, "summary": string (at most 240 UTF-8 bytes)}], "add_ruled_out": [string]} — retain important evidence across rounds; refs must be successful observations or executed ToolFacts from this sample. Summaries and ruled-out hypotheses remain your interpretations, not verified verdicts`,
	ActionFormalizeContract: `{"lead_id": string, "contract": CaseInvariantV2 (see CASE CONTRACTS)} — bind a precise obligation to source you have read now. Correct any returned validation errors in a later round. Accepted contracts persist without being repeated in done`,
	ActionCloseLead:         `{"lead_id": string, "reason": string, "fact_refs": [string]} — archive a question with at least one current-sample evidence reference. Closing is an investigation decision, not proof of safety and does not discard accepted contracts`,
	"twe_playbook_detail":   `{"twe_id": string (e.g. "TWE-STATE-001")} — returns the FULL investigation method for one TWE: attacker capabilities, investigation steps, required evidence, common defenses, and common false positives. Your system prompt carries only the brief tier; pull the detail for any TWE you are actually investigating`,
	"done":                  `{"summary": string, "case_invariants": [CaseInvariantV2 (see CASE CONTRACTS; optional)], "candidates": [{"id": string, "kind": string, "priority": "high"|"medium"|"low", "paths": [string], "symbols": [string], "why_selected": [string], "sink_category": string, "confidence": float (0.0-1.0)}], "investigations": [{"twe_ids": [string], "invariant_ids": [string], "architecture_refs": [string], "classification": "standard"|"variant" (only meaningful with exactly one twe_id — see APPROACH), "filled_roles": {"<role>": {"path": string, "start_line": int, "symbol": string}}, "missing_roles": [string], "required_evidence": [string], "counterevidence": [string], "coverage_gaps": [string], "tool_fact_refs": [string]}] (optional)}`,
}

// BuildSystemPrompt returns the system prompt for one planner phase.
//
// The two phases get different prompts because they have different jobs,
// and because what is in the prompt decides what the model does far more
// reliably than what the prompt asks of it.
//
// Reconnaissance (Pass A, §6.4) is project-first: the program index and the
// project map, nothing else. No TWE catalog, no obligations wiki, no
// Architecture Model, no Project Invariants. The goal is to find the
// semantic breaks and implied contracts this project has, including the
// ones no catalog names.
//
// Investigation (Pass B) restores the TWE catalog and the obligations, so
// the Planner can check whether a known threat has a role or a lifecycle
// its own reading missed. §6.4 is explicit that a TWE may only raise a new
// question — never produce a Case directly.
//
// obligationsBlock should be the string returned by LoadObligations, and is
// rendered in the investigation phase only. Pass "" to skip it entirely.
func BuildSystemPrompt(availableActions []string, obligationsBlock string, knowledge PriorKnowledge, phase string) string {
	var b strings.Builder

	if phase == PhaseInvestigation {
		b.WriteString("You are TEECheck's L3 security audit planner (Investigator, §7.5). You have opened an audit lead of your own: a question about this project's code, grounded in facts you observed. Your job now is to expand it — read the bodies, follow the relations, and find out whether the contract you suspect is broken actually is — and to record what you found as bounded, source-anchored investigations. You do not render a final vulnerability verdict.\n\n")
		b.WriteString(caseContractInstructions)
	} else {
		b.WriteString("You are TEECheck's L3 security audit planner. Your job in this phase is to understand THIS project from its own code: what it is built out of, how its parts call each other, and which of its relations the project map cannot explain.\n\n")
		b.WriteString("You are not looking for known vulnerability patterns and you have not been given any. The questions worth asking here are this project's own:\n")
		b.WriteString("  - a producer and a consumer that disagree about the same field;\n")
		b.WriteString("  - a check on one object and a use of a different one;\n")
		b.WriteString("  - a validation far away from the effect it is supposed to protect;\n")
		b.WriteString("  - a default, an error path or a recovery path that changes the meaning;\n")
		b.WriteString("  - a cross-module call carrying an assumption neither side states;\n")
		b.WriteString("  - two implementations of the same thing that differ in a way nothing explains;\n")
		b.WriteString("  - functions that are each fine and whose combined lifecycle is not.\n\n")
		b.WriteString("These are directions to think in, not rules to match. When you can state one as a question about specific definitions, and cite the observations that raised it, call open_audit_lead.\n\n")
	}

	b.WriteString("CRITICAL RULES:\n")
	b.WriteString("  - An unanswered question — an open lead, a missing role — is YOUR NEXT INVESTIGATIVE TASK. It is NOT a vulnerability conclusion, and it is NOT evidence of safety. Keep investigating until you answer it, exhaust your budget, or have concrete evidence the thing does not exist in this codebase.\n")
	b.WriteString("  - Zero results is not a negative result. A fact_layer_query that returns \"unresolved\" or \"unsupported\" or zero locations, a caller list that came back empty, a ripgrep with no matches: each proves only that nothing was found within that scope (§6.5). Never conclude safety from an absence of a match. Every browsing action tells you the scope of what it could see and what it could not cover — read it, and say which one you mean.\n")
	b.WriteString("  - Anything you did not look at is a coverage gap, never a safe area.\n")
	b.WriteString("  - You do not decide the final vulnerability verdict. Report what you found — Expert/Challenger/Verifier judge it afterward.\n\n")

	if phase == PhaseInvestigation && strings.TrimSpace(knowledge.TWEText) != "" {
		b.WriteString("=== TWE PRIOR KNOWLEDGE (a coverage check on the lead you opened, not a list to go looking for) ===\n")
		b.WriteString(knowledge.TWEText)
		b.WriteString("\n\n")
	}

	if phase == PhaseInvestigation && strings.TrimSpace(obligationsBlock) != "" {
		b.WriteString("SECURITY OBLIGATIONS TO KEEP IN MIND (curated wiki, treat these as the review criteria a downstream human auditor will apply):\n")
		b.WriteString(obligationsBlock)
		b.WriteString("\n\n")
	}

	b.WriteString("AVAILABLE ACTIONS (use the EXACT arg names shown — wrong names are silently ignored):\n")
	for _, name := range availableActions {
		if phase != PhaseInvestigation && (name == ActionUpdateLead || name == ActionFormalizeContract || name == ActionCloseLead) {
			continue
		}
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
	if phase == PhaseInvestigation {
		b.WriteString("  1. Expand the lead you opened: read the bodies of its target definitions, and follow the relations the question depends on.\n")
		b.WriteString("  2. Look for the evidence that would settle it EITHER way. A lead you close because the contract holds is as complete an answer as one you confirm.\n")
		b.WriteString("  3. Use fact_layer_query when a structural question needs a real answer rather than a reading.\n")
		b.WriteString("  4. Check the TWE catalog above against what you found: does a known threat need a role or a lifecycle stage your reading did not cover? If so, that is a new question to investigate — not a finding.\n")
		b.WriteString("  5. Call update_lead to keep short cited evidence notes and ruled-out hypotheses available across rounds. Use formalize_contract as soon as a precise obligation has source anchors; correct validation errors while investigation time remains.\n")
		b.WriteString("  6. Close answered leads with cited reasons, then call done. Accepted contracts already persist; include any remaining candidates or investigations and explain missing evidence.\n\n")
	} else {
		b.WriteString("  1. get_repository_card — what this project says it is, how it builds, and what the index can and cannot answer.\n")
		b.WriteString("  2. list_modules — the parts, with their sizes. Sizes are how you tell the project's own code from vendored dependencies.\n")
		b.WriteString("  3. list_functions on several modules, and get_function_card on the definitions that look load-bearing. Cover more than one part of the project: what you never open, you cannot have an opinion about.\n")
		b.WriteString("  4. get_callers to ask how something is reached. find_symbols resolves a name to candidate ids when more than one definition shares it — pick by id, never by name.\n")
		b.WriteString("  5. read_file and ripgrep when the index cannot answer, or to see the code behind a card.\n")
		b.WriteString("  6. open_audit_lead when you can state a question about specific definitions and cite the observations that raised it.\n\n")
	}

	b.WriteString("HINTS:\n")
	b.WriteString("  - Every observation is printed with a ref (ref=obs:...). That ref is how you cite it in reason_fact_refs. A reason with no ref is refused.\n")
	b.WriteString("  - Match ripgrep globs to the target's source languages; skip lockfiles, build manifests, and docs.\n")
	b.WriteString("  - The round prompt tells you how many rounds remain. Call done before they run out.\n\n")

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
	fmt.Fprintf(&b, "rounds: %d/%d\n", budget.RoundsUsed, budget.TotalRounds())
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

	b.WriteString(leadMemoryBlock(state, 8192))
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
