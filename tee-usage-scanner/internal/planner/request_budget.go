package planner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

const minimumReplyTokens = 256

// A byte is a conservative upper bound for ordinary text tokenizers. Reserve
// framing overhead as well; provider usage remains the final accounting source.
func requestInputUpperBound(system, prompt string) int { return len(system) + len(prompt) + 256 }

// convergencePrompt drops large navigation pages but retains source evidence
// and the exact observed-path whitelist. Its size is bounded before a request
// is sent, so an expensive final prompt cannot consume its own reply reserve.
func convergencePrompt(state *PlannerState, observed map[string]bool, available int) (string, string) {
	system := "You are TEECheck's security audit planner. Return one JSON object with actions containing EXACTLY ONE done action. Report only source-grounded candidates. Missing coverage is not a vulnerability. Never invent evidence or paths."
	var b strings.Builder
	b.WriteString("FINAL ROUND — token/round budget reserve. You MUST call done now; no exploration actions. Use {\"actions\":[{\"name\":\"done\",\"args\":{\"summary\":\"...\",\"candidates\":[]}}]}.\n")
	b.WriteString("OBSERVED PATHS (the only paths that may be cited):\n")
	paths := make([]string, 0, len(observed))
	for p := range observed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	maxBytes := available - minimumReplyTokens - len(system) - 256
	if maxBytes > 12000 {
		maxBytes = 12000
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	for _, p := range paths {
		if b.Len()+len(p)+2 > maxBytes/2 {
			break
		}
		fmt.Fprintf(&b, "%s\n", p)
	}
	b.WriteString("Recent successful observations (excerpts; do not infer absence outside them):\n")
	for i := len(state.Rounds) - 1; i >= 0; i-- {
		for _, o := range state.Rounds[i].Observations {
			if !o.OK {
				continue
			}
			data, _ := json.Marshal(o)
			if b.Len()+len(data)+1 > maxBytes {
				continue
			}
			b.Write(data)
			b.WriteByte('\n')
		}
	}
	prompt := b.String()
	if len(prompt) > maxBytes && maxBytes > 0 {
		prompt = prompt[:maxBytes]
	}
	return system, prompt
}

func accountedUsage(response llm.GenerateResponse, inputUpperBound int) (int, int) {
	in, out := response.Usage.PromptTokens, response.Usage.CompletionTokens
	if in <= 0 {
		in = inputUpperBound
	}
	if out <= 0 {
		out = len(response.Text)
	}
	if total := response.Usage.TotalTokens; total > in+out {
		out = total - in
	}
	return in, out
}
