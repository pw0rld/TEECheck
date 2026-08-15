package trustirfacts

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// TestTableDigest_StableAndSensitive: the provenance digest must be stable
// for an identical table value and must change when the table changes —
// that is the whole point of naming the exact table revision on a fact.
func TestTableDigest_StableAndSensitive(t *testing.T) {
	a := FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "f", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		ProducedStructs:     []string{"s"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "g", Kind: "state_restore_acceptance"}},
	}
	b := a // identical value
	da, err := tableDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := tableDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db || len(da) != 64 {
		t.Errorf("digest not stable/hex256: %q vs %q", da, db)
	}

	b.RollbackFields = []string{"epoch"}
	dc, err := tableDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if dc == da {
		t.Error("digest must change when the table changes")
	}
}

// TestRun_CarriesFactTableProvenance (codex-R1 finding 8): every Run
// outcome past table resolution carries fact_source and the table digest —
// including unresolved ones (provenance is about the table, not the
// outcome) — with the shipped_fixture / llm_annotated split following the
// actual source.
func TestRun_CarriesFactTableProvenance(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "det_fn", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "auth_fn", Kind: "state_restore_acceptance"}},
	})
	eng := &fakeEngine{available: false} // unresolved: provenance must survive anyway
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}

	fact, err := Run(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatalf("Run returned a Go error: %v", err)
	}
	if fact.FactSource != "shipped_fixture" {
		t.Errorf("FactSource = %q, want shipped_fixture", fact.FactSource)
	}
	if len(fact.FactTableSHA256) != 64 || strings.ContainsAny(fact.FactTableSHA256, "ghijklmnopqrstuvwxyz") {
		t.Errorf("FactTableSHA256 = %q, want 64 lowercase hex", fact.FactTableSHA256)
	}
	fixtureDigest := fact.FactTableSHA256

	// Same repository, LLM-annotated table: source flips, digest changes.
	t.Cleanup(ResetFactTables)
	SetFactTable(repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "llm_fn", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "auth_fn", Kind: "state_restore_acceptance"}},
	})
	fact2, err := Run(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatalf("Run returned a Go error: %v", err)
	}
	if fact2.FactSource != "llm_annotated" {
		t.Errorf("FactSource = %q, want llm_annotated after SetFactTable", fact2.FactSource)
	}
	if fact2.FactTableSHA256 == fixtureDigest {
		t.Error("different table must yield a different digest")
	}
}

// TestPersist_RejectsDigestMismatch (codex-R1 MEDIUM 3): a same-FactID
// artifact persisted under a DIFFERENT fact table must not be silently
// reused — that would misreport the new table's result as the old
// persisted evidence.
func TestPersist_RejectsDigestMismatch(t *testing.T) {
	runDir := t.TempDir()
	base := newFact(Request{
		RunDir: runDir, Repository: "https://github.com/OP-TEE/optee_os", Commit: "abc",
		Operation: OperationRollbackVersionPropagation,
	})
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)

	factA := base
	factA.Status = StatusUnresolved
	factA.Locations = []artifacts.ToolLocation{}
	factA.FactSource = "shipped_fixture"
	factA.FactTableSHA256 = digestA
	if _, err := Persist(runDir, factA); err != nil {
		t.Fatalf("initial persist failed: %v", err)
	}

	factB := factA
	factB.FactTableSHA256 = digestB
	if _, err := Persist(runDir, factB); err == nil {
		t.Fatal("persisting a different table under the same FactID must be rejected, got nil error")
	} else if !strings.Contains(err.Error(), "different fact table") {
		t.Errorf("error should explain the digest mismatch, got: %v", err)
	}

	// Same digest, same source: idempotent reuse, no error.
	if _, err := Persist(runDir, factA); err != nil {
		t.Errorf("same-table repersist must reuse silently, got: %v", err)
	}

	// Same digest but DIFFERENT source (fixture → llm_annotated): stale
	// provenance must not be silently reused — source controls
	// blind-discovery scoring (codex-R2 finding 4).
	factC := factA
	factC.FactSource = "llm_annotated"
	if _, err := Persist(runDir, factC); err == nil {
		t.Error("same digest under a different fact_source must be rejected, got nil error")
	}
}
