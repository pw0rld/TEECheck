package planner

import (
	"encoding/json"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// observePresentedEntrySources uses the request that actually went to the
// model, not the requested file range or a full blob omitted from its prompt.
// Both normal round rendering and compact final-round JSON are supported.
func observePresentedEntrySources(recon *ReconState, state *PlannerState, prompt string) {
	shown := map[string]string{}
	lines := strings.Split(prompt, "\n")
	const marker = "  [read_file] OK  ref="
	for i, line := range lines {
		if strings.HasPrefix(line, marker) {
			ref := strings.TrimPrefix(line, marker)
			var body []string
			for j := i + 1; j < len(lines) && strings.HasPrefix(lines[j], "    "); j++ {
				body = append(body, strings.TrimPrefix(lines[j], "    "))
			}
			shown[ref] = strings.Join(body, "\n")
			continue
		}
		if strings.HasPrefix(line, "{") {
			var o artifacts.RoundObservation
			if json.Unmarshal([]byte(line), &o) == nil && o.OK && o.Name == "read_file" && o.Ref != "" {
				shown[o.Ref] = o.Output
			}
		}
	}
	for _, round := range state.Rounds {
		for _, o := range round.Observations {
			body, ok := shown[o.Ref]
			if !ok || !o.OK || o.Name != "read_file" || o.ActionIndex < 0 || o.ActionIndex >= len(round.Actions) {
				continue
			}
			act := round.Actions[o.ActionIndex]
			if act.Name != "read_file" {
				continue
			}
			prefix := strings.SplitN(body, "\n... (scrollback:", 2)[0]
			if !strings.HasPrefix(o.Output, strings.TrimRight(prefix, "\n")) {
				continue
			}
			// Keep the original cut boundary. The scrollback renderer adds a
			// newline before its marker even when it cuts inside a source line.
			recon.ObserveEntrySourceOutput(act.Name, act.Args, prefix, true)
		}
	}
}
