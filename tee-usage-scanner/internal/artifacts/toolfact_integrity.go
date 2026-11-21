package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const TaintTraceOperation = "cpp.taint.trace"

// ToolFactContentSHA256 covers the canonical ToolFact with only the digest
// itself omitted. References to persisted files additionally bind file bytes.
func ToolFactContentSHA256(f ToolFact) string {
	f.ContentSHA256 = ""
	data, _ := json.Marshal(f)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ValidateToolFactContent(f ToolFact) error {
	if f.Operation == TaintTraceOperation {
		if f.ContentSHA256 == "" || f.Scope == nil || f.Scope.RepoURL == "" || f.RepoCommit == "" || f.Scope.Commit != f.RepoCommit {
			return fmt.Errorf("taint ToolFact requires a content digest and matching pinned source scope")
		}
	}
	if f.ContentSHA256 != "" && f.ContentSHA256 != ToolFactContentSHA256(f) {
		return fmt.Errorf("ToolFact content hash mismatch")
	}
	return nil
}
