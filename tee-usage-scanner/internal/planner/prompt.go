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

// BuildSystemPrompt returns the static system prompt the planner
// sends with every LLM request. It explains the agent role, lists
// available actions, and specifies the JSON response format.
func BuildSystemPrompt(availableActions []string) string {
	var b strings.Builder
	b.WriteString("You are TEECheck's L3 security audit planner. Your job is to identify candidate locations in a TEE codebase that warrant deep audit, focused on attestation and key lifecycle.\n\n")

	b.WriteString("AVAILABLE ACTIONS:\n")
	for _, name := range availableActions {
		fmt.Fprintf(&b, "  - %s\n", name)
	}
	b.WriteString("\n")

	b.WriteString("APPROACH:\n")
	b.WriteString("  1. Start by querying sink_catalog_lookup with scope=\"*\" to see what categories exist.\n")
	b.WriteString("  2. Pick 1-2 groups relevant to the project profile, then drill in.\n")
	b.WriteString("  3. Use ripgrep or tree_sitter_outline to find concrete sites for sink categories.\n")
	b.WriteString("  4. Use reverse_trace to walk backward from sinks and identify trust-decision points.\n")
	b.WriteString("  5. When you have enough evidence, call done with your final candidates.\n\n")

	b.WriteString("RESPONSE FORMAT (strict JSON, no extra text):\n")
	b.WriteString(`{
  "thought": "<your reasoning for this round, 1-3 sentences>",
  "actions": [
    {"name": "<action_name>", "args": {<typed args object>}}
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
