package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const TaintTraceOperation = "cpp.taint.trace"
const TaintPrescanOperation = "cpp.taint.prescan"

// IsTaintOperation identifies immutable may-flow evidence, not a verdict.
func IsTaintOperation(operation string) bool {
	return operation == TaintTraceOperation || operation == TaintPrescanOperation
}

// ToolFactContentSHA256 covers the canonical ToolFact with only the digest
// itself omitted. References to persisted files additionally bind file bytes.
func ToolFactContentSHA256(f ToolFact) string {
	f.ContentSHA256 = ""
	data, _ := json.Marshal(f)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ValidateToolFactContent(f ToolFact) error {
	if IsTaintOperation(f.Operation) {
		if f.ContentSHA256 == "" || f.Scope == nil || f.Scope.RepoURL == "" || f.RepoCommit == "" || f.Scope.Commit != f.RepoCommit {
			return fmt.Errorf("taint ToolFact requires a content digest and matching pinned source scope")
		}
	}
	if f.ContentSHA256 != "" && f.ContentSHA256 != ToolFactContentSHA256(f) {
		return fmt.Errorf("ToolFact content hash mismatch")
	}
	return nil
}
