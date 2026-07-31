package trustirfacts

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// withTestFactTable temporarily registers table under repository's
// normalized key so Run's happy-path tests can drive the real
// clone→build→materialize→analyze pipeline against a local, offline,
// throwaway git repository instead of the real OP-TEE remote — this
// package's tests must never depend on network reachability. The real
// registry entry (facttable.go's knownFactTables) is restored afterward.
func withTestFactTable(t *testing.T, repository string, table FactTable) {
	t.Helper()
	key := normalizeRepo(repository)
	old, hadOld := knownFactTables[key]
	knownFactTables[key] = table
	t.Cleanup(func() {
		if hadOld {
			knownFactTables[key] = old
		} else {
			delete(knownFactTables, key)
		}
	})
}

// localRepo creates a one-commit local git repository and returns its path
// and HEAD commit — a stand-in "remote" cloneAtRevision can clone offline.
func localRepo(t *testing.T) (path, commit string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "--quiet")
	git(t, dir, "config", "user.email", "test@test.com")
	git(t, dir, "config", "user.name", "test")
	writeAndCommit(t, dir, "signed_hdr.c", "// stand-in source\n", "init")
	return dir, headCommit(t, dir)
}

func TestRun_UnsupportedRepository(t *testing.T) {
	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: "https://example.com/unregistered", Commit: "abc",
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run returned a Go error for a domain-level outcome: %v", err)
	}
	if fact.Status != StatusUnsupported {
		t.Errorf("Status = %q, want %q", fact.Status, StatusUnsupported)
	}
	if fact.Error == "" {
		t.Error("expected a non-empty Error explaining the unsupported status")
	}
	if eng.createDBCalls != 0 || eng.analyzeCalls != 0 {
		t.Error("an unsupported repository must never reach the engine (no faked evidence gathering)")
	}
}

func TestRun_UnsupportedOperation(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: "no-such-operation", QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusUnsupported {
		t.Errorf("Status = %q, want %q", fact.Status, StatusUnsupported)
	}
}

func TestRun_EngineUnavailable(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	eng := &fakeEngine{available: false}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusUnresolved {
		t.Errorf("Status = %q, want %q (CodeQL unavailable must never read as 'no vulnerability')", fact.Status, StatusUnresolved)
	}
}

func TestRun_DatabaseBuildFailure(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	eng := &fakeEngine{available: true, createDBErr: errBoom}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusUnresolved {
		t.Errorf("Status = %q, want %q", fact.Status, StatusUnresolved)
	}
	if !strings.Contains(fact.Error, "boom") {
		t.Errorf("Error = %q, want it to carry the underlying build failure", fact.Error)
	}
}

func TestRun_AnalyzeFailure(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	eng := &fakeEngine{available: true, analyzeErr: errBoom}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusUnresolved {
		t.Errorf("Status = %q, want %q (a nonzero codeql exit must be unresolved, not silently clean)", fact.Status, StatusUnresolved)
	}
	if eng.createDBCalls != 1 {
		t.Errorf("createDBCalls = %d, want 1 (the db must still build even though analyze then fails)", eng.createDBCalls)
	}
}

func TestRun_MaterializeFailureIsError(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: "does-not-exist",
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusError {
		t.Errorf("Status = %q, want %q (our own plumbing failed, not the target's evidence)", fact.Status, StatusError)
	}
	if eng.analyzeCalls != 0 {
		t.Error("analyze must not run once the query pack failed to materialize")
	}
}

func TestRun_Success_VulnerableFindsLocations(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		ProducedStructs:     []string{"shdr_pub_key"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{
		available: true,
		analyzeResults: []codeql.Result{
			{
				RuleID:    "teecheck/trustir-cpp/twe-state-001",
				Message:   "TWE-STATE-001: producer never propagates rollback field 'version'; authority therefore checks a default version.",
				Path:      "core/crypto/signed_hdr.c",
				StartLine: 262, EndLine: 262,
				Related: []codeql.RelatedLocation{
					{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
					{Path: "core/kernel/ree_fs_ta.c", StartLine: 639, Symbol: "check_update_version"},
				},
			},
		},
	}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusSuccess {
		t.Fatalf("Status = %q, want %q (error=%q)", fact.Status, StatusSuccess, fact.Error)
	}
	if len(fact.Locations) != 1 || fact.Locations[0].Path != "core/crypto/signed_hdr.c" {
		t.Errorf("Locations = %+v, want the flagged producer's location", fact.Locations)
	}
	// The query's conclusion and the sites it names must land on the fact.
	// Keeping only Locations is what left five agent prompts with a line
	// number and no mention of check_update_version at all.
	if len(fact.Findings) != 1 {
		t.Fatalf("Findings = %+v, want the analyze result's message carried through", fact.Findings)
	}
	if fact.Findings[0].Message == "" {
		t.Error("the message is the query's answer; it must reach the fact")
	}
	if len(fact.Findings[0].Related) != 2 {
		t.Errorf("Related = %+v, want both named sites", fact.Findings[0].Related)
	} else if fact.Findings[0].Related[1].Symbol != "check_update_version" {
		t.Errorf("Related[1] = %+v, want the authority call site", fact.Findings[0].Related[1])
	}
	if fact.ArtifactRef == "" {
		t.Error("expected ArtifactRef to point at the built database (§23.3: visible run-directory artifact)")
	}
	if fact.RepoCommit != commit {
		t.Errorf("RepoCommit = %q, want %q", fact.RepoCommit, commit)
	}
	if fact.ArgumentsSHA256 == "" {
		t.Error("expected ArgumentsSHA256 to be populated")
	}
	if len(fact.CoverageGaps) == 0 {
		t.Error("expected disclosed coverage gaps on a first-slice deterministic result")
	}
}

// TestRun_Success_FixedIsCleanNotError proves §6.5: zero query results is a
// legitimate success (the structural gap the query looks for is genuinely
// absent), not an error and not "unresolved".
func TestRun_Success_FixedIsCleanNotError(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{available: true, analyzeResults: nil}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusSuccess {
		t.Errorf("Status = %q, want %q (empty results must not be misreported)", fact.Status, StatusSuccess)
	}
	if len(fact.Locations) != 0 {
		t.Errorf("Locations = %+v, want empty", fact.Locations)
	}
}

// TestRun_DatabaseBuiltOnceAcrossCalls is the §23.3 acceptance criterion:
// "same repo+commit+operation+args → cache hit, DB built once".
func TestRun_DatabaseBuiltOnceAcrossCalls(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{available: true}
	runDir := t.TempDir()
	req := Request{
		RunDir: runDir, Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}

	first, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	second, err := Run(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if first.Status != StatusSuccess || second.Status != StatusSuccess {
		t.Fatalf("both calls should succeed: first=%q (%s) second=%q (%s)", first.Status, first.Error, second.Status, second.Error)
	}
	if eng.createDBCalls != 1 {
		t.Errorf("createDBCalls = %d, want 1 across two identical requests", eng.createDBCalls)
	}
	if eng.analyzeCalls != 2 {
		t.Errorf("analyzeCalls = %d, want 2 (only the database is cached, not the query run)", eng.analyzeCalls)
	}
	// Second call's fact carries the "reused from a prior build" gap.
	foundReuseNote := false
	for _, gap := range second.CoverageGaps {
		if strings.Contains(gap, "reused") {
			foundReuseNote = true
		}
	}
	if !foundReuseNote {
		t.Error("expected the second call's CoverageGaps to disclose the database cache hit")
	}
}

func TestRun_RequestValidationIsAGoError(t *testing.T) {
	eng := &fakeEngine{available: true}
	_, err := Run(context.Background(), eng, Request{})
	if err == nil {
		t.Fatal("an invalid Request must be a Go error, not a fact with a status")
	}
}

func TestRunAndPersist_WritesFactToRunDir(t *testing.T) {
	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{available: true}
	runDir := t.TempDir()
	req := Request{
		RunDir: runDir, Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, path, err := RunAndPersist(context.Background(), eng, req)
	if err != nil {
		t.Fatalf("RunAndPersist: %v", err)
	}
	if fact.Status != StatusSuccess {
		t.Fatalf("Status = %q (error=%q)", fact.Status, fact.Error)
	}
	if path == "" {
		t.Fatal("expected a non-empty persisted path")
	}
}
