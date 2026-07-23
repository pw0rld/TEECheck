package runfs

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// ReadProjectInvariants must consume the exact wrapper object the invariants
// stage persists ({schema_version, run_id, invariants:[...]}), not a bare
// array. Before this helper existed every consumer unmarshalled the wrapper
// into []ProjectInvariant, which always errored and silently yielded no
// invariants downstream.
func TestReadProjectInvariants_ReadsProductionWrapperFormat(t *testing.T) {
	runDir := t.TempDir()

	written := artifacts.ProjectInvariants{
		SchemaVersion: "teecheck.project_invariants.v1",
		RunID:         "run-1",
		Invariants: []artifacts.ProjectInvariant{
			{InvariantID: "inv-1", Statement: "version must propagate", Status: "proposed"},
		},
	}
	if err := WriteJSON(ProjectInvariantsPath(runDir), written); err != nil {
		t.Fatal(err)
	}

	got, err := ReadProjectInvariants(runDir)
	if err != nil {
		t.Fatalf("ReadProjectInvariants: %v", err)
	}
	if len(got) != 1 || got[0].InvariantID != "inv-1" {
		t.Fatalf("invariants = %+v, want the single inv-1 from the wrapper", got)
	}
}
