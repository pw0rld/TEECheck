package architecture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// ─── Negative fixtures (§22: "配套一组故意造假的 fixture 作为负例测试:
// 不存在的文件、存在但符号不匹配、行号漂移") ─────────────────────────

func TestValidateAndDowngrade_NonexistentFile(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-1", Kind: "asset", Name: "WalletState", State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "source", File: "src/does_not_exist.rs", StartLine: 1, EndLine: 3, Note: "WalletState"}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)

	if got.Assets[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown (no dependencies to fall back to inferred)", got.Assets[0].State)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %d, want 1", len(adjustments))
	}
	if adjustments[0].FromState != artifacts.EvidenceObserved || adjustments[0].ToState != artifacts.EvidenceUnknown {
		t.Errorf("adjustment = %+v", adjustments[0])
	}
	if got.Assets[0].Description == "" {
		t.Error("downgrade must be recorded in Description, not only in the returned slice")
	}
}

func TestValidateAndDowngrade_LineRangeOutOfBounds(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "state.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("struct WalletState {\n    balance: u64,\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-1", Kind: "asset", Name: "WalletState", State: artifacts.EvidenceObserved,
			// File has 3 lines; this citation names lines 50-60.
			Evidence: []artifacts.EvidenceReference{{Kind: "source", File: "src/state.rs", StartLine: 50, EndLine: 60, Note: "WalletState"}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)

	if got.Assets[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown", got.Assets[0].State)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %d, want 1", len(adjustments))
	}
}

func TestValidateAndDowngrade_SymbolNotPresentAtCitedLocation(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "state.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	// A real file, a real (in-range) line range — but the claimed symbol
	// does not appear anywhere in it. This is the "existing file, wrong
	// symbol" fixture: a file-exists-only check would wrongly accept it.
	if err := os.WriteFile(src, []byte("fn unrelated() {\n    do_something();\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-1", Kind: "asset", Name: "WalletState", State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "source", File: "src/state.rs", StartLine: 1, EndLine: 3, Note: "WalletState"}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)

	if got.Assets[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown (symbol not present)", got.Assets[0].State)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %d, want 1", len(adjustments))
	}
	if adjustments[0].Reason == "" {
		t.Error("reason must explain the symbol mismatch")
	}
}

// downgradeTarget: an observed statement that DOES carry dependency refs
// downgrades to inferred, not all the way to unknown.
func TestValidateAndDowngrade_DowngradesToInferredWhenDependenciesPresent(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-1", Kind: "asset", Name: "WalletState", State: artifacts.EvidenceObserved,
			Dependencies: []string{"component-host-storage"},
			Evidence:     []artifacts.EvidenceReference{{Kind: "source", File: "missing.rs", StartLine: 1, EndLine: 1}},
		}},
	}
	got, _ := ValidateAndDowngrade(model, repo)
	if got.Assets[0].State != artifacts.EvidenceInferred {
		t.Fatalf("state = %q, want inferred", got.Assets[0].State)
	}
}

func TestValidateAndDowngrade_DocumentedAlsoDowngrades(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		TrustAssumptions: []artifacts.ArchitectureElement{{
			ID: "assume-1", Kind: "trust_assumption", Name: "OperatorHonesty", State: artifacts.EvidenceDocumented,
			Evidence: []artifacts.EvidenceReference{{Kind: "doc", File: "docs/missing.md", StartLine: 1, EndLine: 2}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.TrustAssumptions[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown", got.TrustAssumptions[0].State)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %d, want 1", len(adjustments))
	}
}

// No evidence at all on an observed statement is exactly as invalid as a
// broken citation — citations.ValidateFacts calls this "unanchored" and
// this validator treats it identically: strict, no silent pass.
func TestValidateAndDowngrade_NoEvidenceAtAllDowngrades(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		Roles: []artifacts.ArchitectureElement{{
			ID: "role-1", Kind: "role", Name: "Validator", State: artifacts.EvidenceObserved,
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.Roles[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown", got.Roles[0].State)
	}
	if len(adjustments) != 1 || adjustments[0].Reason == "" {
		t.Fatalf("adjustments = %+v", adjustments)
	}
}

// ─── Positive fixture: a real, valid citation must NOT be downgraded ────

func TestValidateAndDowngrade_ValidCitationSurvives(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "core", "crypto", "signed_hdr.c")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "TEE_Result shdr_load_pub_key(const struct shdr *shdr, size_t offs,\n" +
		"\t\t\t     const uint8_t *ns_img, size_t ns_img_size,\n" +
		"\t\t\t     struct shdr_pub_key *key)\n{\n\treturn TEE_SUCCESS;\n}\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		Entrypoints: []artifacts.ArchitectureElement{{
			ID: "entrypoint-shdr-load-pub-key", Kind: "entrypoint", Name: "shdr_load_pub_key",
			State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{
				Kind: "source", File: "core/crypto/signed_hdr.c", StartLine: 1, EndLine: 3,
				Note: "shdr_load_pub_key",
			}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.Entrypoints[0].State != artifacts.EvidenceObserved {
		t.Fatalf("state = %q, want observed (citation is valid)", got.Entrypoints[0].State)
	}
	if len(adjustments) != 0 {
		t.Fatalf("adjustments = %+v, want none", adjustments)
	}
}

// The same fixture against the real CVE-2026-44362 checkout (§22's
// rollback acceptance scenario source), proving the validator works
// against the actual benchmark corpus, not just synthetic temp files.
func TestValidateAndDowngrade_RealCVEFixture(t *testing.T) {
	repoRoot := "../../../teecheck-benchmark/datasets/CVE-2026-44362/vulnerable"
	if _, err := os.Stat(repoRoot); err != nil {
		t.Skipf("benchmark fixture not present at %s: %v", repoRoot, err)
	}
	model := artifacts.ArchitectureModel{
		Entrypoints: []artifacts.ArchitectureElement{{
			ID: "entrypoint-shdr-load-pub-key", Kind: "entrypoint", Name: "shdr_load_pub_key",
			State: artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{
				Kind: "source", File: "core/crypto/signed_hdr.c", StartLine: 262, EndLine: 266,
				Note: "shdr_load_pub_key",
			}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repoRoot)
	if got.Entrypoints[0].State != artifacts.EvidenceObserved {
		t.Fatalf("state = %q, adjustments=%+v, want observed", got.Entrypoints[0].State, adjustments)
	}
}

// ─── §22 prompt constraints this package enforces mechanically ─────────

// "documented/inferred may never be promoted to observed": a valid
// citation on a documented (or inferred) statement must not bump it to
// observed — only the model's own declared state, subject to downgrade,
// is ever used.
func TestValidateAndDowngrade_NeverPromotesDocumentedOrInferred(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "docs", "arch.md")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("The Host cannot roll back sealed state.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		TrustAssumptions: []artifacts.ArchitectureElement{
			{
				ID: "doc-1", Kind: "trust_assumption", Name: "Host", State: artifacts.EvidenceDocumented,
				Evidence: []artifacts.EvidenceReference{{Kind: "doc", File: "docs/arch.md", StartLine: 1, EndLine: 1, Note: "Host"}},
			},
			{
				ID: "inf-1", Kind: "trust_assumption", Name: "Host", State: artifacts.EvidenceInferred,
				Dependencies: []string{"doc-1"},
			},
		},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.TrustAssumptions[0].State != artifacts.EvidenceDocumented {
		t.Errorf("documented statement with a valid citation was changed to %q, must stay documented", got.TrustAssumptions[0].State)
	}
	if got.TrustAssumptions[1].State != artifacts.EvidenceInferred {
		t.Errorf("inferred statement was changed to %q, must stay inferred (inferred is never citation-checked or promoted)", got.TrustAssumptions[1].State)
	}
	if len(adjustments) != 0 {
		t.Errorf("no adjustments expected, got %+v", adjustments)
	}
}

// "unknown must survive — the agent may not guess to complete its JSON":
// an unknown-state element with zero evidence is left exactly as-is —
// the validator never fills in a guessed evidence list or state for it.
func TestValidateAndDowngrade_UnknownSurvivesWithoutEvidence(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		Unknowns: []artifacts.ArchitectureElement{{
			ID: "unk-1", Kind: "role", Name: "MysteryComponent", State: artifacts.EvidenceUnknown,
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.Unknowns[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unchanged unknown", got.Unknowns[0].State)
	}
	if len(got.Unknowns[0].Evidence) != 0 {
		t.Errorf("evidence should stay empty, not guessed: %+v", got.Unknowns[0].Evidence)
	}
	if len(adjustments) != 0 {
		t.Errorf("unknown statements are not citation-checked, want no adjustments, got %+v", adjustments)
	}
}

// NormalizeStates: a missing or invented state string defaults to
// unknown, never to a stronger guessed state (e.g. "inferred").
func TestNormalizeStates_MissingOrInvalidStateDefaultsToUnknown(t *testing.T) {
	model := artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{
			{ID: "c-1", Kind: "component", Name: "X", State: ""},
			{ID: "c-2", Kind: "component", Name: "Y", State: artifacts.EvidenceState("verified")},
			{ID: "c-3", Kind: "component", Name: "Z", State: artifacts.EvidenceObserved},
		},
	}
	got, adjustments := NormalizeStates(model)
	if got.Components[0].State != artifacts.EvidenceUnknown {
		t.Errorf("empty state -> %q, want unknown", got.Components[0].State)
	}
	if got.Components[1].State != artifacts.EvidenceUnknown {
		t.Errorf("invalid state -> %q, want unknown", got.Components[1].State)
	}
	if got.Components[2].State != artifacts.EvidenceObserved {
		t.Errorf("valid state was changed to %q", got.Components[2].State)
	}
	if len(adjustments) != 2 {
		t.Fatalf("adjustments = %d, want 2 (only the two bad ones)", len(adjustments))
	}
}

// Relations get existence+range validation even though they have no
// Name-shaped symbol fallback (see the package doc comment).
func TestValidateAndDowngrade_RelationWithoutNoteChecksExistenceOnly(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "boundary.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("ecall_restore(...);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		Boundaries: []artifacts.ArchitectureRelation{{
			ID: "boundary-1", Kind: "trust_boundary", From: "party-host", To: "component-enclave",
			State:    artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "source", File: "src/boundary.rs", StartLine: 1, EndLine: 1}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.Boundaries[0].State != artifacts.EvidenceObserved {
		t.Fatalf("state = %q, want observed (existence+range checks out, no symbol asserted)", got.Boundaries[0].State)
	}
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none", adjustments)
	}
}

func TestValidateAndDowngrade_RelationNonexistentFileDowngrades(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		DataFlows: []artifacts.ArchitectureRelation{{
			ID: "flow-1", Kind: "data_flow", From: "party-host", To: "component-enclave",
			State:    artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "source", File: "src/missing.rs", StartLine: 1, EndLine: 1}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.DataFlows[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown", got.DataFlows[0].State)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %d, want 1", len(adjustments))
	}
}

// Path-only evidence (StartLine == 0, as fingerprint-v2 emits for manifest/
// path-kind signals) validates on existence alone — no symbol check.
func TestValidateAndDowngrade_PathOnlyEvidenceExistenceOnly(t *testing.T) {
	repo := t.TempDir()
	manifestPath := filepath.Join(repo, "enclave.config.xml")
	if err := os.WriteFile(manifestPath, []byte("<EnclaveConfiguration/>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{{
			ID: "component-manifest-1", Kind: "manifest", Name: "SGX enclave configuration",
			State:    artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: "enclave.config.xml"}},
		}},
	}
	got, adjustments := ValidateAndDowngrade(model, repo)
	if got.Components[0].State != artifacts.EvidenceObserved {
		t.Fatalf("state = %q, want observed (file exists)", got.Components[0].State)
	}
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none", adjustments)
	}
}

func TestValidateAndDowngrade_PathOnlyEvidenceMissingFileDowngrades(t *testing.T) {
	repo := t.TempDir()
	model := artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{{
			ID: "component-manifest-1", Kind: "manifest", Name: "SGX enclave configuration",
			State:    artifacts.EvidenceObserved,
			Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: "does-not-exist.xml"}},
		}},
	}
	got, _ := ValidateAndDowngrade(model, repo)
	if got.Components[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown", got.Components[0].State)
	}
}
