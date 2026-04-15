package planner

import (
	"fmt"
	"strings"
)

// PromptProfile is the minimal view of the project profile the
// planner injects into the round prompt. It is a subset of
// artifacts.ProjectProfile to keep the prompt small and decoupled
// from upstream schema changes.
type PromptProfile struct {
	RepoURL        string
	Commit         string
	Focus          string
	Languages      []string
	FrameworkHints []string
	FileCount      int
}

// actionArgSchemas documents the exact args shape each action
// expects. Used by BuildSystemPrompt so the LLM does not guess at
// parameter names — guessing leads to silent failures like the LLM
// passing include_patterns when the ripgrep handler wants globs.
//
// Keep entries terse (one line each). When a new action is added
// to the registry, add a matching entry here.
var actionArgSchemas = map[string]string{
	"list_dir":            `{"path": string (repo-relative), "depth": int (0-3)}`,
	"read_file":           `{"path": string (repo-relative), "start": int (1-indexed), "end": int (1-indexed, 0 for cap)}`,
	"ripgrep":             `{"pattern": string (regex), "globs": [string] (e.g. ["*.rs"])}`,
	"tree_sitter_outline": `{"path": string (must end in .rs)}`,
	"reverse_trace":       `{"file": string (where the symbol is defined, must end in .rs), "symbol": string (function name), "depth": int (1-3, default 1)} — walks backward through .rs files, returns a tree of who calls the symbol and who calls THOSE callers up to depth levels; use this to ask "who calls X?" in one step instead of running many ripgreps`,
	"sink_catalog_lookup": `{"scope": string ("*" | "<group>" | "<group>.<category>")}`,
	"legacy_keyword_scan": `{"run_dir": string (absolute), "max_hotspots": int (optional)}`,
	"repomix_summarize":   `{"path": string (repo-relative), "compress": bool (optional)}`,
	"done":                `{"summary": string, "candidates": [{"id": string, "kind": string, "priority": "high"|"medium"|"low", "paths": [string], "symbols": [string], "why_selected": [string], "sink_category": string, "confidence": float (0.0-1.0)}]}`,
}

// BuildSystemPrompt returns the static system prompt the planner
// sends with every LLM request. It explains the agent role, lists
// available actions with typed arg schemas, optionally inlines the
// curated obligations wiki, and specifies the JSON response format.
//
// obligationsBlock should be the string returned by LoadObligations.
// Pass "" to skip the obligations section entirely.
func BuildSystemPrompt(availableActions []string, obligationsBlock string) string {
	var b strings.Builder
	b.WriteString("You are TEECheck's L3 security audit planner. Your job is to identify candidate locations in a TEE codebase that warrant deep audit, focused on attestation and key lifecycle.\n\n")

	if strings.TrimSpace(obligationsBlock) != "" {
		b.WriteString("SECURITY OBLIGATIONS TO KEEP IN MIND (curated wiki, treat these as the review criteria a downstream human auditor will apply):\n")
		b.WriteString(obligationsBlock)
		b.WriteString("\n\n")
	}

	b.WriteString("AVAILABLE ACTIONS (use the EXACT arg names shown — wrong names are silently ignored):\n")
	for _, name := range availableActions {
		schema, ok := actionArgSchemas[name]
		if !ok {
			schema = "{...}"
		}
		fmt.Fprintf(&b, "  - %s  args=%s\n", name, schema)
	}
	b.WriteString("\n")

	b.WriteString("APPROACH:\n")
	b.WriteString("  1. Start by querying sink_catalog_lookup with scope=\"*\" to see what groups exist, then drill in.\n")
	b.WriteString("  2. Use ripgrep with globs=[\"*.rs\"] to find concrete sites for sink symbols — SKIP Cargo.lock/toml/md files.\n")
	b.WriteString("  3. When you find a relevant .rs file, use tree_sitter_outline to get its structure before reading.\n")
	b.WriteString("  4. Use read_file on the specific function/impl ranges the outline reveals.\n")
	b.WriteString("  5. DO NOT WASTE ROUNDS. Aim for 1-2 good candidates by round 5-6, then call done.\n")
	b.WriteString("  6. When you have evidence, call done with candidates containing {id, kind, priority, paths, symbols, why_selected}. kind should be one of: attestation, key_management, authorization, state_machine, ffi_boundary, runtime_entry.\n\n")

	b.WriteString("HINTS:\n")
	b.WriteString("  - Ignore Cargo.lock, Cargo.toml, CHANGELOG.md. Always pass globs=[\"*.rs\"] to ripgrep.\n")
	b.WriteString("  - Directories to prioritize for TEE work: attest/, enclave-boundary/, sgx/, fog/*/enclave/, consensus/enclave/.\n")
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

// BuildRoundPrompt assembles the user-message prompt for a single
// planner round. It includes the project profile, accumulated
// candidates, the trailing window of recent observations, and the
// remaining budget.
func BuildRoundPrompt(state *PlannerState, profile PromptProfile, budget Budget) string {
	var b strings.Builder

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
	if len(profile.Languages) > 0 {
		fmt.Fprintf(&b, "languages: %s\n", strings.Join(profile.Languages, ", "))
	}
	if len(profile.FrameworkHints) > 0 {
		fmt.Fprintf(&b, "frameworks: %s\n", strings.Join(profile.FrameworkHints, ", "))
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

	recent := state.LastRoundsForPrompt(2)
	if len(recent) > 0 {
		b.WriteString("=== RECENT ROUNDS ===\n")
		for _, r := range recent {
			fmt.Fprintf(&b, "round %d:\n", r.Round)
			if r.Thought != "" {
				fmt.Fprintf(&b, "  thought: %s\n", r.Thought)
			}
			for _, obs := range r.Observations {
				if obs.OK {
					fmt.Fprintf(&b, "  [%s] OK\n", obs.Name)
				} else {
					fmt.Fprintf(&b, "  [%s] ERROR: %s\n", obs.Name, obs.Error)
				}
				if obs.Output != "" {
					trimmed := obs.Output
					if len(trimmed) > 1500 {
						trimmed = trimmed[:1500] + "\n... (truncated)"
					}
					fmt.Fprintf(&b, "    %s\n", strings.ReplaceAll(trimmed, "\n", "\n    "))
				}
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("=== NEXT ===\n")
	b.WriteString("What is your next action? Reply with strict JSON in the format from the system prompt.\n")
	return b.String()
}
