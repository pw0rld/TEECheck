package invariants

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// TestRollbackAcceptanceScenario_CVE202644362Shape is §22's named
// acceptance scenario: on the CVE-2026-44362 shape (OP-TEE's subkey
// rollback-version propagation bug — a signed TA subkey header carries a
// subkey_version that shdr_load_pub_key never copies into the runtime
// shdr_pub_key, so check_update_version always receives 0 and the
// rollback database never advances), the Invariant Agent must be able to
// produce an obligation of the form: loaded/restored security version
// state must be propagated to the rollback check and compared against
// version state that cannot be rolled back with it, before it influences
// TA/key/authority decisions.
//
// Per this PR's testing constraint, no live model is called — a stub LLM
// returns the canned response a correctly-behaving model would produce for
// this architecture. What this test actually proves is the PLUMBING: that
// such an obligation, once produced, survives BuildLLM's parsing and
// Validate's checks unstripped, with its real citation into the actual
// CVE-2026-44362 checkout still resolving. It is not a claim that the live
// GLM model reliably generates this content — that is a live-model quality
// question outside what a deterministic, offline test suite can check (see
// this PR's final report).
func TestRollbackAcceptanceScenario_CVE202644362Shape(t *testing.T) {
	repoRoot := "../../../teecheck-benchmark/datasets/CVE-2026-44362/vulnerable"
	if _, err := os.Stat(repoRoot); err != nil {
		t.Skipf("benchmark fixture not present at %s: %v", repoRoot, err)
	}

	// The Architecture Model the Architecture Agent would already have
	// produced and citation-validated for this repo: the entrypoint that
	// parses the signed subkey header, and the asset it should propagate
	// a version into.
	model := artifacts.ArchitectureModel{
		Entrypoints: []artifacts.ArchitectureElement{{
			ID: "entrypoint-shdr-load-pub-key", Kind: "entrypoint", Name: "shdr_load_pub_key",
			State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{
				Kind: "source", File: "core/crypto/signed_hdr.c", StartLine: 262, EndLine: 266,
				Note: "shdr_load_pub_key",
			}},
		}},
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-shdr-pub-key-version", Kind: "asset", Name: "shdr_pub_key.version",
			State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{
				Kind: "source", File: "core/crypto/signed_hdr.c", StartLine: 262, EndLine: 266,
				Note: "shdr_pub_key",
			}},
		}},
	}

	statement := "The subkey_version loaded from a signed TA subkey header must be " +
		"propagated into the runtime shdr_pub_key state before it reaches " +
		"check_update_version, and compared there against rollback-database " +
		"version state that cannot be rolled back together with the subkey " +
		"itself, before that state influences TA loading / key / authority " +
		"decisions."

	resp := map[string]any{
		"invariants": []map[string]any{
			{
				"invariant_id":        "INV-STATE-002",
				"statement":           statement,
				"related_twes":        []string{"TWE-STATE-001"},
				"entrypoints":         []string{"shdr_load_pub_key"},
				"authority_points":    []string{"check_update_version", "ree_fs_ta_open"},
				"required_properties": []string{"state_freshness", "version_continuity"},
				"expected_defenses":   []string{"monotonic_rollback_database"},
				"architecture_refs":   []string{"entrypoint-shdr-load-pub-key", "asset-shdr-pub-key-version"},
				"verification_plan": []string{
					"trace subkey->subkey_version from shdr_load_pub_key's parsed header into key->version",
					"trace key->version into check_update_version's argument at ree_fs_ta_open",
					"confirm the rollback database rejects a subkey chain whose recorded version regresses",
				},
				"unresolved_assumptions": []string{
					"check_update_version's own rollback-database comparison logic is not in this checkout; not verified here",
				},
				"evidence": []map[string]any{
					{"kind": "source", "file": "core/crypto/signed_hdr.c", "start_line": 262, "end_line": 266, "note": "shdr_load_pub_key"},
				},
				"status": "violated_candidate", // must be overwritten to proposed
			},
		},
	}
	data, _ := json.Marshal(resp)
	stub := &stubClient{responseJSON: string(data)}

	built, err := BuildLLM(context.Background(), stub, Input{Model: model, TWEContext: "TWE-STATE-001"}, 0.2)
	if err != nil {
		t.Fatalf("BuildLLM: %v", err)
	}
	if len(built) != 1 {
		t.Fatalf("built = %+v, want 1 invariant", built)
	}

	got, adjustments := Validate(built[0], model, repoRoot)

	if got.Status != "proposed" {
		t.Fatalf("status = %q, want proposed regardless of what the model claimed", got.Status)
	}
	for _, want := range []string{"propagat", "compared", "check_update_version", "TA loading", "before"} {
		if !strings.Contains(got.Statement, want) {
			t.Errorf("statement missing %q: %s", want, got.Statement)
		}
	}
	if len(got.RelatedTWEs) != 1 || got.RelatedTWEs[0] != "TWE-STATE-001" {
		t.Errorf("related_twes = %v, want the rollback TWE", got.RelatedTWEs)
	}
	if len(got.ArchitectureRefs) != 2 {
		t.Errorf("architecture_refs = %v, want both real refs kept (referential integrity checked, nothing dangling here)", got.ArchitectureRefs)
	}
	if len(got.VerificationPlan) == 0 {
		t.Error("verification_plan must be concrete and non-empty")
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence = %+v, want the real citation into signed_hdr.c to survive validation", got.Evidence)
	}
	// Only the status override should have fired — everything else in
	// this fixture is already well-formed (real TWE, real architecture
	// refs, a resolvable citation).
	if len(adjustments) != 1 || adjustments[0].Kind != "status_override" {
		t.Errorf("adjustments = %+v, want exactly one status_override", adjustments)
	}
}
