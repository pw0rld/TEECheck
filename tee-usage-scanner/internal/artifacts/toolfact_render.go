package artifacts

import (
	"fmt"
	"strconv"
	"strings"
)

// ToolFinding is one result the tool produced: what it concluded, where, and
// the other sites that conclusion refers to.
//
// A thin-shell query's answer lives in this message. RollbackVersionNotPropagated
// computes "producer $@ never propagates rollback field '<f>'; authority $@
// (<kind>) therefore checks a default version" and resolves each $@ to a real
// symbol and line. Keeping only the primary location threw away the finding
// and left the consumer — the authority call the whole weakness depends on —
// unmentioned.
type ToolFinding struct {
	Message  string         `json:"message"`
	Location ToolLocation   `json:"location"`
	Related  []ToolLocation `json:"related,omitempty"`
}

// FormatToolFact renders one ToolFact for an agent prompt.
//
// It lives here, next to the type, rather than in one of the agent packages
// because all four consumers (expert, challenger, verifier, arbiter) render
// the same thing — they previously kept three copies of a locations-only
// formatter, which is how the message stayed dropped in every one of them at
// once.
func FormatToolFact(f ToolFact) string {
	if IsTaintOperation(f.Operation) {
		return formatTaintFact(f)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s/%s status=%s", f.FactID, f.Tool, f.Operation, f.Status)
	if f.Error != "" {
		fmt.Fprintf(&b, " error=%s", f.Error)
	}
	if len(f.Findings) == 0 {
		if len(f.Locations) > 0 {
			fmt.Fprintf(&b, " locations=%s", FormatToolLocations(f.Locations))
			return b.String()
		}
		// Say it. An empty tail reads as "the field was never populated";
		// "we ran this and matched nothing" is a different, real answer.
		b.WriteString(" (ran, no match)")
		return b.String()
	}
	for _, fi := range f.Findings {
		fmt.Fprintf(&b, "\n    at %s: %s", formatLoc(fi.Location), fi.Message)
		for _, r := range fi.Related {
			fmt.Fprintf(&b, "\n      - %s", formatLoc(r))
		}
	}
	return b.String()
}

// FormatToolLocations renders a location list as "path:line, path:line".
func FormatToolLocations(locs []ToolLocation) string {
	if len(locs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(locs))
	for _, l := range locs {
		parts = append(parts, formatLoc(l))
	}
	return strings.Join(parts, ", ")
}

func formatLoc(l ToolLocation) string {
	s := l.Path + ":" + strconv.Itoa(l.StartLine)
	if l.Symbol != "" {
		s += " " + l.Symbol
	}
	return s
}
