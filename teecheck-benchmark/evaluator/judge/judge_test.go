package judge

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/rag"
)

func TestPromptContainsReportAndCandidate(t *testing.T) {
	p, err := Prompt(rag.Report{RunID: "scan-1"}, rag.Hit{CaseID: "CVE-1", Case: rag.Case{Weakness: "key binding"}})
	if err != nil || !strings.Contains(p, "scan-1") || !strings.Contains(p, "key binding") {
		t.Fatalf("prompt missing evaluator context: %q, %v", p, err)
	}
}
