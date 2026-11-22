package artifacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrescanReviewRendersRankedPathsBeforeAlgorithmNoise(t *testing.T) {
	fact := ToolFact{FactID: "prescan", Operation: TaintPrescanOperation, Status: "success", Result: json.RawMessage(`{"total_paths":2,"ranked_candidates":[{"path_index":1},{"path_index":1},{"path_index":-1},{"path_index":100},{}]}`), Paths: [][]ToolPathStep{
		{{Location: ToolLocation{Path: "lib/ciphers/aes.c", StartLine: 1}, Message: "S-box lookup"}},
		{{Location: ToolLocation{Path: "core/tee/service.c", StartLine: 10, Symbol: "entry"}, Message: "input"}, {Location: ToolLocation{Path: "core/tee/copy.c", StartLine: 20, Symbol: "memcpy"}, Message: "length"}},
	}}
	text := FormatToolFact(fact)
	if !strings.Contains(text, "core/tee/service.c") || strings.Contains(text, "S-box lookup") || strings.Count(text, "core/tee/service.c") != 1 {
		t.Fatalf("review ignored ranked candidates: %s", text)
	}
	if len(text) > 8192 || !strings.Contains(text, "do NOT prove safety") || !strings.Contains(text, "1 other witness paths") {
		t.Fatalf("review lost bounds/count/uncertainty: %s", text)
	}
}

func TestPrescanToolFactRequiresContentDigestAndScope(t *testing.T) {
	for _, operation := range []string{TaintTraceOperation, TaintPrescanOperation} {
		if err := ValidateToolFactContent(ToolFact{Operation: operation}); err == nil {
			t.Fatalf("%s accepted without immutable source identity", operation)
		}
	}
}
