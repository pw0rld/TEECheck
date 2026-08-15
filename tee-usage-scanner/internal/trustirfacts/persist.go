package trustirfacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
// rewriting — UNLESS the two facts were produced by different fact tables.
// FactID is deterministic in (repository, commit, operation) — see
// Request.factID — but SetFactTable can change the table driving a run
// within the same run directory, and silently reusing the earlier fact
// would misreport the new table's result as persisted evidence. A
// fact-table digest mismatch is therefore an error: the caller reruns in
// a fresh run directory (or with the same table as the earlier fact).
func Persist(runDir string, fact artifacts.ToolFact) (string, error) {
	path := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	// Always absolute: see the note above on validateToolFactRefs.
	if abs, aerr := filepath.Abs(path); aerr == nil {
		path = abs
	}
	if _, err := os.Stat(path); err == nil {
		var existing artifacts.ToolFact
		if rerr := runfs.ReadJSON(path, &existing); rerr == nil &&
			(existing.FactTableSHA256 != fact.FactTableSHA256 || existing.FactSource != fact.FactSource) {
			return "", fmt.Errorf("tool fact %s already persisted at %s under a different fact table (source %q digest %q, new %q %q): rerun in a fresh run directory or restore the original table",
				fact.FactID, path, existing.FactSource, existing.FactTableSHA256, fact.FactSource, fact.FactTableSHA256)
		}
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
