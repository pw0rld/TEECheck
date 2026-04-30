package citations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFacts_Unanchored(t *testing.T) {
	results := ValidateFacts([]CitedFact{
		{Text: "claim with no anchor", Cited: nil},
	}, "/some/repo")
	if len(results) != 1 {
		t.Fatalf("len=%d want 1", len(results))
	}
	if results[0].Status != StatusUnanchored {
		t.Errorf("Status=%q want %q", results[0].Status, StatusUnanchored)
	}
	if results[0].FactText != "claim with no anchor" {
		t.Errorf("FactText=%q", results[0].FactText)
	}
}

func TestValidateFacts_Unresolved(t *testing.T) {
	// Empty repoRoot → cannot validate even if citation looks valid.
	results := ValidateFacts([]CitedFact{
		{Text: "claim", Cited: []CitedBytes{
			{File: "x.rs", StartLine: 1, EndLine: 2,
				StartByte: 0, EndByte: 4, SHA256: "abc"},
		}},
	}, "")
	if len(results) != 1 {
		t.Fatalf("len=%d want 1", len(results))
	}
	if results[0].Status != StatusUnresolved {
		t.Errorf("Status=%q want %q", results[0].Status, StatusUnresolved)
	}
	if results[0].Reason == "" {
		t.Error("Reason should explain why unresolved")
	}
}

func TestValidateFacts_UnresolvedRepoMissing(t *testing.T) {
	results := ValidateFacts([]CitedFact{
		{Text: "claim", Cited: []CitedBytes{
			{File: "x.rs", StartLine: 1, EndLine: 2,
				StartByte: 0, EndByte: 4, SHA256: "abc"},
		}},
	}, "/nonexistent/repo/path")
	if results[0].Status != StatusUnresolved {
		t.Errorf("Status=%q want %q", results[0].Status, StatusUnresolved)
	}
}

func TestValidateFacts_Valid(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "x.rs")
	if err := os.WriteFile(src, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(CitedBytes{File: "x.rs", StartLine: 2, EndLine: 2}, repo)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	results := ValidateFacts([]CitedFact{
		{Text: "fresh claim", Cited: []CitedBytes{resolved}},
	}, repo)
	if results[0].Status != StatusValid {
		t.Errorf("Status=%q want %q (Reason=%q)", results[0].Status, StatusValid, results[0].Reason)
	}
}

func TestValidateFacts_StaleSHA256Mismatch(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "x.rs")
	if err := os.WriteFile(src, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, _ := Resolve(CitedBytes{File: "x.rs", StartLine: 2, EndLine: 2}, repo)

	// Mutate the file: cited line changes content → sha256 mismatch.
	if err := os.WriteFile(src, []byte("a\nB-modified\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	results := ValidateFacts([]CitedFact{
		{Text: "drifted claim", Cited: []CitedBytes{resolved}},
	}, repo)
	if results[0].Status != StatusStale {
		t.Errorf("Status=%q want %q", results[0].Status, StatusStale)
	}
	if results[0].Reason == "" {
		t.Error("Reason should describe the drift")
	}
}

func TestValidateFacts_StaleAnyCitationFails(t *testing.T) {
	// 5 citations, 4 valid + 1 file-missing → Status=stale (strict).
	repo := t.TempDir()
	src := filepath.Join(repo, "x.rs")
	if err := os.WriteFile(src, []byte("a\nb\nc\nd\ne\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	good := []CitedBytes{}
	for i := 1; i <= 4; i++ {
		r, err := Resolve(CitedBytes{File: "x.rs", StartLine: i, EndLine: i}, repo)
		if err != nil {
			t.Fatal(err)
		}
		good = append(good, r)
	}
	missing := CitedBytes{File: "doesnotexist.rs", StartLine: 1, EndLine: 1}

	results := ValidateFacts([]CitedFact{
		{Text: "mostly-fine fact", Cited: append(good, missing)},
	}, repo)
	if results[0].Status != StatusStale {
		t.Errorf("Status=%q want %q (one bad citation should mark fact stale)", results[0].Status, StatusStale)
	}
}

func TestValidateFacts_PreservesText(t *testing.T) {
	results := ValidateFacts([]CitedFact{
		{Text: "first"},
		{Text: "second"},
	}, "")
	if len(results) != 2 {
		t.Fatalf("len=%d", len(results))
	}
	if results[0].FactText != "first" || results[1].FactText != "second" {
		t.Errorf("FactText drift: %+v", results)
	}
}

// ─── ResolveFacts / FlattenFacts moved here from internal/expert ────

func TestResolveFacts_StrictPartialFailureClearsCited(t *testing.T) {
	// V1.1.2 polish (C1): partial-failure now downgrades the fact
	// to unanchored. Previously the fact kept surviving citations
	// and HasValidCitation reported true, mirroring text into the
	// validated SupportingFacts surface — a silent contract
	// violation (depends-on-A-and-B claim with B failing).
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "x.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	in := []CitedFact{
		{Text: "good", Cited: []CitedBytes{
			{File: "src/x.rs", StartLine: 1, EndLine: 1},
		}},
		{Text: "partial", Cited: []CitedBytes{
			{File: "src/x.rs", StartLine: 2, EndLine: 2}, // would resolve
			{File: "src/missing.rs", StartLine: 1, EndLine: 1},
		}},
		{Text: "all-bad", Cited: []CitedBytes{
			{File: "src/missing.rs", StartLine: 1, EndLine: 1},
		}},
	}
	out, errs := ResolveFacts(in, repo)
	if len(out) != 3 {
		t.Fatalf("len(out)=%d, want 3", len(out))
	}
	if len(out[0].Cited) != 1 || !out[0].Cited[0].Resolved() {
		t.Errorf("good fact: %+v", out[0])
	}
	// Strict policy: partial fact's surviving citation is dropped
	// because the OTHER citation failed.
	if len(out[1].Cited) != 0 {
		t.Errorf("partial fact: kept=%d, want 0 (strict downgrade)", len(out[1].Cited))
	}
	if out[1].Text != "partial" {
		t.Errorf("partial fact text lost: %q", out[1].Text)
	}
	if len(out[2].Cited) != 0 {
		t.Errorf("all-bad fact: kept=%d, want 0", len(out[2].Cited))
	}
	if len(errs) < 2 {
		t.Errorf("expected at least 2 resolve errors, got %d", len(errs))
	}
}

func TestFlattenFacts_OnlyValidatedTextEntersValidated(t *testing.T) {
	resolved := CitedBytes{
		File: "x.rs", StartLine: 1, EndLine: 1,
		StartByte: 0, EndByte: 2, SHA256: "abc",
	}
	in := []CitedFact{
		{Text: "validated", Cited: []CitedBytes{resolved}},
		{Text: "unanchored", Cited: nil},
		{Text: "validated 2", Cited: []CitedBytes{resolved}}, // dup citation
	}
	text, pool := FlattenFacts(in)
	if len(text) != 2 {
		t.Errorf("text=%v, want 2 entries", text)
	}
	for _, s := range text {
		if s == "unanchored" {
			t.Errorf("unanchored leaked: %v", text)
		}
	}
	if len(pool) != 1 {
		t.Errorf("pool=%d, want 1 (deduped)", len(pool))
	}
}
