package trustirfacts

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// Persist schema-validates fact against schemas/trustir-tool.v1.json's
// "result" variant and writes it to its canonical path
// (runfs.TrustIRToolFactPath). A non-nil error here means the fact this
// package built does not satisfy the wire contract — a bug in this package,
// caught before an invalid artifact reaches disk.
//
// ToolFact is documented as immutable after persistence (see
// artifacts.ToolFact's doc comment): if a file already exists at the target
// path, Persist treats it as already-written and returns its path without
// rewriting. FactID is deterministic in (repository, commit, operation) —
// see Request.factID — so an existing file at that path was written by an
// earlier call with identical inputs, not a different fact that happens to
// collide.
func Persist(runDir string, fact artifacts.ToolFact) (string, error) {
	path := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	data, err := json.Marshal(fact)
	if err != nil {
		return "", fmt.Errorf("marshal tool fact %s: %w", fact.FactID, err)
	}
	if err := schema.Validate(schema.TrustIRToolV1, data); err != nil {
		return "", fmt.Errorf("tool fact %s failed schema validation: %w", fact.FactID, err)
	}
	if err := runfs.WriteJSON(path, fact); err != nil {
		return "", fmt.Errorf("write tool fact %s: %w", fact.FactID, err)
	}
	return path, nil
}
