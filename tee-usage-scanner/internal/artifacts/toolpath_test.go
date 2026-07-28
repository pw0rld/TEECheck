package artifacts

import (
	"fmt"
	"strings"
	"testing"
)

func TestFormatToolPath_RendersAnOrderedReadablePath(t *testing.T) {
	steps := []ToolPathStep{
		{
			Location: ToolLocation{Path: "core/crypto/signed_hdr.c", StartLine: 262, EndLine: 270, Symbol: "shdr_load_pub_key"},
			Kind:     "source",
			Message:  "signed version read from the header",
		},
		{
			Location: ToolLocation{Path: "core/tee/tee_rollback.c", StartLine: 91, Symbol: "rollback_check"},
			Message:  "guard reads a different field",
		},
	}

	got := FormatToolPath(steps)

	for _, want := range []string{
		"core/crypto/signed_hdr.c:262-270",
		"shdr_load_pub_key",
		"[source]",
		"signed version read from the header",
		"core/tee/tee_rollback.c:91",
		"rollback_check",
		"guard reads a different field",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered path missing %q:\n%s", want, got)
		}
	}

	// Ordering is the whole point of a path: step 1 must precede step 2.
	if strings.Index(got, "signed_hdr.c") > strings.Index(got, "tee_rollback.c") {
		t.Errorf("steps rendered out of order:\n%s", got)
	}
	if strings.Contains(got, "omitted") {
		t.Errorf("short path must not claim truncation:\n%s", got)
	}
}

func TestFormatToolPath_EmptyRendersNone(t *testing.T) {
	if got := FormatToolPath(nil); got != "(none)" {
		t.Errorf("FormatToolPath(nil) = %q, want %q", got, "(none)")
	}
	if got := FormatToolPath([]ToolPathStep{}); got != "(none)" {
		t.Errorf("FormatToolPath(empty) = %q, want %q", got, "(none)")
	}
}

// A truncated attack path that does not say it was truncated is a lie:
// the reader (a model) would take the last rendered step for the end of
// the traced flow. The cap must therefore announce itself and state the
// real length.
func TestFormatToolPath_TruncationIsAnnouncedWithTheRealLength(t *testing.T) {
	total := MaxRenderedPathSteps + 3
	steps := make([]ToolPathStep, 0, total)
	for i := 0; i < total; i++ {
		steps = append(steps, ToolPathStep{
			Location: ToolLocation{Path: "src/x.c", StartLine: i + 1},
			Message:  "step",
		})
	}

	got := FormatToolPath(steps)

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != MaxRenderedPathSteps+1 {
		t.Fatalf("rendered %d lines, want %d steps + 1 truncation notice:\n%s", len(lines), MaxRenderedPathSteps, got)
	}
	notice := lines[len(lines)-1]
	if !strings.Contains(notice, "omitted") {
		t.Errorf("last line does not announce truncation: %q", notice)
	}
	if !strings.Contains(notice, fmt.Sprintf("%d", total-MaxRenderedPathSteps)) {
		t.Errorf("truncation notice does not name how many steps were dropped: %q", notice)
	}
	if !strings.Contains(notice, fmt.Sprintf("%d", total)) {
		t.Errorf("truncation notice does not name the real path length: %q", notice)
	}
}
