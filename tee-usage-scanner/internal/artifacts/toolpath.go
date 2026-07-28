package artifacts

import (
	"fmt"
	"strings"
)

// MaxRenderedPathSteps bounds how many steps of a ToolPathStep sequence
// FormatToolPath writes into an agent prompt.
//
// The number is a guard against a pathological trace, not a working
// limit: an attack path an agent can reason about is a handful of steps
// (source, the hops that carry the value, the enforcement point), and
// every agent prompt this renders into also has to fit the source
// snippets, the ToolFacts and the architecture slice inside one context
// window. 20 leaves any realistic traced path untouched while stopping a
// runaway trace from crowding out the code the agent must re-ground
// against.
//
// A path that hits the cap is NOT silently shortened: FormatToolPath
// appends a line naming how many steps were dropped and how long the real
// path is. A model shown 20 of 200 steps with no notice would read the
// last rendered step as the end of the flow.
const MaxRenderedPathSteps = 20

// FormatToolPath renders an ordered ToolPathStep sequence as one numbered
// step per line, e.g.
//
//  1. core/crypto/signed_hdr.c:262-270 shdr_load_pub_key [source] — signed version read from the header
//  2. core/tee/tee_rollback.c:91 rollback_check — guard reads a different field
//
// It lives here, next to the ToolPathStep definition, rather than in one
// of the agent packages because all four consumers (expert, challenger,
// verifier, arbiter) render the same field and must not drift into four
// slightly different attack-path formats.
//
// Empty input renders as "(none)" so a prompt section never appears with
// nothing under its header.
func FormatToolPath(steps []ToolPathStep) string {
	if len(steps) == 0 {
		return "(none)"
	}

	shown := steps
	truncated := 0
	if len(steps) > MaxRenderedPathSteps {
		shown = steps[:MaxRenderedPathSteps]
		truncated = len(steps) - MaxRenderedPathSteps
	}

	lines := make([]string, 0, len(shown)+1)
	for i, step := range shown {
		var b strings.Builder
		fmt.Fprintf(&b, "%d. %s", i+1, formatToolLocationRef(step.Location))
		if step.Location.Symbol != "" {
			fmt.Fprintf(&b, " %s", step.Location.Symbol)
		}
		if step.Kind != "" {
			fmt.Fprintf(&b, " [%s]", step.Kind)
		}
		if step.Message != "" {
			fmt.Fprintf(&b, " — %s", step.Message)
		}
		lines = append(lines, b.String())
	}
	if truncated > 0 {
		lines = append(lines, fmt.Sprintf("... (%d further step(s) omitted; the traced path is %d steps long — this is a truncated view, not the end of the flow)", truncated, len(steps)))
	}
	return strings.Join(lines, "\n")
}

// formatToolLocationRef renders a ToolLocation as path:start[-end], the
// same file:line shape agents are told to cite back at us.
func formatToolLocationRef(loc ToolLocation) string {
	path := loc.Path
	if path == "" {
		path = "(unknown file)"
	}
	if loc.EndLine > loc.StartLine {
		return fmt.Sprintf("%s:%d-%d", path, loc.StartLine, loc.EndLine)
	}
	return fmt.Sprintf("%s:%d", path, loc.StartLine)
}
