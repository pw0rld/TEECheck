package agentbus

import (
	"fmt"
	"strings"
)

// DefaultResponseCap bounds how much of an inter-agent answer reaches the
// asking agent's prompt.
//
// The bus was the one tool boundary in this system with no limit at all.
// Every other one has had a cap for as long as it has existed — reverse_trace
// stops at 30k bytes and 30 callers per level, ripgrep and read_file bound
// their own output, fact_layer_query caps locations and findings. A bus
// handler could return anything, and on 2026-08-02 one did: scanner-001,
// asked a question in English, split the question into keywords, matched them
// against a 3291-file repository, and returned every matching line. The
// verifier's follow-up prompt reached 82,191,625 bytes — 99.94% of it that
// one answer, starting from .checkpatch.conf. The request never came back;
// three retries at ten minutes each were spent, and the run died.
//
// 32 KiB is chosen against what a useful answer actually looks like rather
// than against a token budget: a struct definition, a handful of call sites,
// a function body. Answers that legitimately need more than this are a
// finding about the question, not about the cap.
const DefaultResponseCap = 32 * 1024

// TruncationInfo reports what a cap removed, so the caller can record it.
// Empty Marker means nothing was cut.
type TruncationInfo struct {
	OriginalBytes int
	Limit         int
	// Full is the complete, uncut response body — kept so a caller with a
	// blob store can persist it and put the ref where a human can follow it.
	Full string
}

// responseBytes is what an answer costs a prompt: the answer plus every
// fact, since that is how the asking stages render it.
func responseBytes(r Response) int {
	n := len(r.Answer)
	for _, f := range r.Facts {
		n += len(f) + 2 // the "; " each renderer joins on
	}
	return n
}

// capResponse cuts an over-long answer down to the cap and says so, in the
// answer text, in a way the reading model cannot mistake for completeness.
//
// The marker is the point. Truncation that looks like a complete answer is
// worse than no answer: the model acts on a partial result believing it has
// the whole one, and nothing downstream can tell the difference. So the
// preview is labelled as a preview, the omitted count is stated, and the
// blob reference is named — three separate signals that this is not all of
// it.
//
// Facts are cut whole rather than mid-string. A half-written "path:line"
// is not a shorter fact, it is a wrong one, and a citation validator
// downstream would treat it as a fabricated location.
func capResponse(r Response, limit int, blobRef string) (Response, TruncationInfo) {
	total := responseBytes(r)
	if limit <= 0 || total <= limit {
		return r, TruncationInfo{}
	}
	full := renderFull(r)

	// The answer itself comes first: it is the handler's actual reply, and
	// losing it to make room for facts would invert the priority.
	answer := r.Answer
	if len(answer) > limit {
		answer = answer[:limit] + "\n[…answer truncated…]"
	}
	remaining := limit - len(answer)

	kept := make([]string, 0, len(r.Facts))
	used := 0
	for _, f := range r.Facts {
		cost := len(f) + 2
		if used+cost > remaining {
			break
		}
		kept = append(kept, f)
		used += cost
	}

	omitted := len(r.Facts) - len(kept)
	notice := fmt.Sprintf(
		"\n\n[PREVIEW ONLY — this answer was %d bytes and was capped at %d. "+
			"%d of %d results are NOT shown. Do not read the absence of a result "+
			"here as evidence that it does not exist",
		total, limit, omitted, len(r.Facts))
	if blobRef != "" {
		notice += "; the complete answer is recorded at " + blobRef
	}
	notice += ".]"

	r.Answer = answer + notice
	r.Facts = kept
	return r, TruncationInfo{OriginalBytes: total, Limit: limit, Full: full}
}

// renderFull is the uncut body, in the shape a reader would want it: the
// answer, then one fact per line rather than the semicolon-joined single
// line the prompt renderers use.
func renderFull(r Response) string {
	var b strings.Builder
	b.WriteString(r.Answer)
	if len(r.Facts) > 0 {
		b.WriteString("\n\nFacts (" + fmt.Sprint(len(r.Facts)) + "):\n")
		for _, f := range r.Facts {
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
