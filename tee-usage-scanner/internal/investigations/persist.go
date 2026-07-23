package investigations

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// Persist schema-validates inv against schemas/twe-investigation.v1.json
// and writes it to its canonical path (runfs.InvestigationPath, §10:
// runs/<run-id>/03_investigations/<investigation-id>.json). A non-nil error
// means inv does not satisfy the wire contract — a bug in the caller (Build
// always produces a schema-valid shape when given a schema-valid
// WireInvestigation), caught before an invalid artifact reaches disk.
//
// Like trustirfacts.Persist, an investigation ID is deterministic in its
// content (see deriveID), so an existing file at the target path was
// written by an earlier, identical Build/Validate pass — Persist treats
// that as already-written rather than rewriting it.
func Persist(runDir string, inv artifacts.TWEInvestigation) (string, error) {
	path := runfs.InvestigationPath(runDir, inv.InvestigationID)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	data, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("marshal investigation %s: %w", inv.InvestigationID, err)
	}
	if err := schema.Validate(schema.TWEInvestigationV1, data); err != nil {
		return "", fmt.Errorf("investigation %s failed schema validation: %w", inv.InvestigationID, err)
	}
	if err := runfs.WriteJSON(path, inv); err != nil {
		return "", fmt.Errorf("write investigation %s: %w", inv.InvestigationID, err)
	}
	return path, nil
}
