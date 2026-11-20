package runfs

import (
	"encoding/json"
	"errors"
	"os"
)

// LegacyPriorEnabled respects the policy of the run being reviewed, including
// standalone stage reruns. Old artifacts without configuration remain readable;
// new runs explicitly record whether these optional model stages were enabled.
func LegacyPriorEnabled(runDir string) bool {
	data, err := os.ReadFile(ManifestPath(runDir))
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	var manifest struct {
		Configuration map[string]json.RawMessage `json:"configuration"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false
	}
	raw, exists := manifest.Configuration["enable_legacy_prior"]
	if !exists {
		return true // Old manifests had configuration but no policy field.
	}
	var enabled bool
	return json.Unmarshal(raw, &enabled) == nil && enabled
}
