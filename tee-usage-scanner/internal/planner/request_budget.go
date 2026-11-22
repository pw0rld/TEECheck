package planner

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

const minimumReplyTokens = 256
const reasoningReplyTokens = 16384

// Estimate request size without treating every byte of ASCII code as a token.
// Three ASCII bytes/token leaves some margin over common English estimates;
// non-ASCII runes get a separate allowance. This is not a tokenizer or a hard
// upper bound. Actual provider usage remains authoritative, including overruns.
func estimateRequestInputTokens(system, prompt string) int {
	return estimateTextTokens(system) + estimateTextTokens(prompt) + 256
}

func estimateTextTokens(text string) int {
	ascii, other := 0, 0
	for _, r := range text {
		if r < 128 {
			ascii++
		} else {
			other += 2
		}
	}
	return (ascii+2)/3 + other
}

func roleOutputLimit(cfg RunConfig) int {
	if cfg.MaxOutputTokens > 0 {
		return cfg.MaxOutputTokens
	}
	return config.DefaultLLMMaxTokens
}

// Reserve meaningful room for known thinking models, while respecting an
// explicitly smaller role limit. Unknown aliases retain the generic floor.
func minimumRequestOutput(cfg RunConfig) int {
	model := strings.ToLower(strings.TrimSpace(cfg.Model))
	effort := strings.ToLower(strings.TrimSpace(cfg.ReasoningEffort))
	thinking := effort != "" && effort != "none"
	if effort != "none" {
		thinking = thinking || config.DeepSeekThinkingModel(model)
		for _, prefix := range []string{"glm-5", "glm-4.7", "o1", "o3", "o4", "gpt-5", "gpt-6"} {
			thinking = thinking || strings.HasPrefix(model, prefix)
		}
	}
	minimum := minimumReplyTokens
	if thinking {
		minimum = reasoningReplyTokens
	}
	if limit := roleOutputLimit(cfg); limit < minimum {
		minimum = limit
	}
	return minimum
}

func requestOutputBudget(cfg RunConfig, input int, recon, final bool) int {
	limit := roleOutputLimit(cfg)
	allowance := cfg.Budget.OutputAllowance(input, recon, final)
	if allowance != UnlimitedOutputAllowance && allowance < limit {
		return allowance
	}
	return limit
}

// convergencePrompt drops large navigation pages but retains the contract
// interface and real lead identities before adding source evidence. Otherwise
// replacing the normal system prompt at the budget boundary also erases the
// only instructions for turning a candidate into a contract.
//
// Whole records are added only while they fit. A cut must not turn a partial
// source observation or lead identity into something that looks complete.
func convergencePrompt(state *PlannerState, observed map[string]bool, available int) (string, string) {
	return convergencePromptWithMinimum(state, observed, available, minimumReplyTokens)
}

func convergencePromptWithMinimum(state *PlannerState, observed map[string]bool, available, minimum int) (string, string) {
	system := "You are TEECheck's defensive code-contract planner. Return one JSON object with actions containing EXACTLY ONE done action. Define obligations, never verdicts. Missing evidence is not a vulnerability. Never invent evidence, leads, symbols, or paths."
	const maxBytes = 12000
	if available != UnlimitedOutputAllowance && estimateRequestInputTokens(system, "")+minimum > available {
		// The caller's OutputAllowance check will refuse a request which
		// cannot even fit the fixed system instructions and minimum reply.
		return system, ""
	}
	var b strings.Builder
	appendIfFits := func(s string) bool {
		if b.Len()+len(s) > maxBytes {
			return false
		}
		if available != UnlimitedOutputAllowance && estimateRequestInputTokens(system, b.String()+s)+minimum > available {
			return false
		}
		b.WriteString(s)
		return true
	}
	if !appendIfFits("FINAL ROUND — token/round budget reserve. Call done now; no exploration actions. Use {\"actions\":[{\"name\":\"done\",\"args\":{\"summary\":\"...\",\"case_invariants\":[],\"candidates\":[]}}]}.\n") {
		return system, ""
	}
	appendIfFits("CASE CONTRACTS: Prefer case_invariants for grounded obligations. Shape: {\"lead_ref\":\"real lead_id\",\"subjects\":[{\"path\":\"observed path\",\"symbol\":\"observed definition\"}],\"preconditions\":[\"when the obligation applies\"],\"required_property\":{\"kind\":\"property kind\",\"statement\":\"what must hold\"},\"security_effect\":\"decision affected\",\"evidence_refs\":[{\"kind\":\"observation\",\"ref\":\"observed ref\"}],\"verification_queries\":[],\"related_twes\":[]}.\n")
	appendIfFits("AUDIT LEADS (identities and evidence from this sample):\n")
	for i := len(state.AuditLeads) - 1; i >= 0; i-- {
		lead := state.AuditLeads[i]
		if lead.LeadID == "" || (lead.RunID != "" && lead.RunID != state.RunID) {
			continue
		}
		data, _ := json.Marshal(struct {
			LeadID          string               `json:"lead_id"`
			TargetSymbolIDs []artifacts.SymbolID `json:"target_symbol_ids"`
			ReasonFactRefs  []string             `json:"reason_fact_refs"`
		}{lead.LeadID, lead.TargetSymbolIDs, lead.ReasonFactRefs})
		appendIfFits(string(data) + "\n")
	}
	appendIfFits("Use only this sample's real lead IDs and source you read. A subject must match the referenced lead's target. Include observed consumers needed for the preconditions. Leave unsupported verification_queries empty; never weaken the obligation to fit a query. Preserve candidates with missing grounding and explain the gap.\n")

	appendIfFits("OBSERVED PATHS (the only paths that may be cited):\n")
	paths := make([]string, 0, len(observed))
	for p := range observed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// Navigation cannot crowd out all the remaining source evidence.
	pathLimit := b.Len() + (maxBytes-b.Len())/3
	for _, p := range paths {
		if b.Len()+len(p)+1 > pathLimit {
			break
		}
		appendIfFits(p + "\n")
	}
	appendIfFits("Recent successful observations (excerpts; do not infer absence outside them):\n")
	for i := len(state.Rounds) - 1; i >= 0; i-- {
		for _, o := range state.Rounds[i].Observations {
			if !o.OK {
				continue
			}
			data, _ := json.Marshal(o)
			appendIfFits(string(data) + "\n")
		}
	}
	return system, b.String()
}

func accountedUsage(response llm.GenerateResponse, inputEstimate int) (int, int) {
	in, out := response.Usage.PromptTokens, response.Usage.CompletionTokens
	if in <= 0 {
		in = inputEstimate
	}
	if out <= 0 {
		out = len(response.Text)
	}
	if total := response.Usage.TotalTokens; total > in+out {
		out = total - in
	}
	return in, out
}
