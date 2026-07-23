package runfs

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"

// ReadProjectInvariants loads the ProjectInvariants collection the invariants
// stage persists and returns its Invariants slice. The stage writes a wrapper
// object ({schema_version, run_id, invariants:[...]}), so consumers must read
// that shape — unmarshalling the file straight into []ProjectInvariant always
// errors and silently drops every invariant downstream.
func ReadProjectInvariants(runDir string) ([]artifacts.ProjectInvariant, error) {
	var collection artifacts.ProjectInvariants
	if err := ReadJSON(ProjectInvariantsPath(runDir), &collection); err != nil {
		return nil, err
	}
	return collection.Invariants, nil
}
