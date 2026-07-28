package planner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func rich(id string, files ...string) artifacts.CasePack {
	return artifacts.CasePack{
		SchemaVersion:    "teecheck.case_pack.v1",
		CaseID:           id,
		TargetFiles:      files,
		Priority:         "medium",
		CommonDefenses:   []string{"a dominating check already constrains the value"},
		RequiredEvidence: []string{"the check dominates every path"},
	}
}

func thin(id string, prio string, files ...string) artifacts.CasePack {
	return artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        id,
		TargetFiles:   files,
		Priority:      prio,
		WhySelected:   []string{"why-" + id},
	}
}

// 14 of the 29 measured runs have exactly this shape: both sides name the
// same file. The rich pack must win and absorb the thin one's why_selected.
func TestMerge_EqualSetsMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c")},
		[]artifacts.CasePack{thin("cand-1", "high", "a.c")},
	)
	if len(got) != 1 {
		t.Fatalf("want 1 merged pack, got %d", len(got))
	}
	if len(got[0].CommonDefenses) == 0 {
		t.Fatal("merged pack must keep the rich pack's playbook fields")
	}
	if len(got[0].WhySelected) == 0 {
		t.Fatal("merged pack must absorb the thin pack's why_selected")
	}
	if got[0].Priority != "high" {
		t.Fatalf("merged priority must be the higher of the two, got %q", got[0].Priority)
	}
}

// Never observed in the 29 measured runs, but the rule exists to make a
// wrong merge impossible: a partial overlap must NOT collapse two cases.
func TestMerge_PartialOverlapDoesNotMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c", "b.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	if len(got) != 2 {
		t.Fatalf("want 2 packs — a partial overlap must not merge, got %d", len(got))
	}
}

func TestMerge_DisjointDoesNotMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "b.c")},
	)
	if len(got) != 2 {
		t.Fatalf("want 2 packs for disjoint targets, got %d", len(got))
	}
}

func TestMerge_OneSideEmptyKeepsTheOther(t *testing.T) {
	got := Merge([]artifacts.CasePack{rich("inv-1", "a.c")}, nil)
	if len(got) != 1 {
		t.Fatalf("want the rich pack alone, got %d", len(got))
	}
	got = Merge(nil, []artifacts.CasePack{thin("cand-1", "low", "b.c")})
	if len(got) != 1 {
		t.Fatalf("want the thin pack alone, got %d", len(got))
	}
}

// An investigation with every role missing yields a pack with no files to
// look at. Handing that to Expert asks it to hypothesise about nothing.
func TestMerge_DropsEmptyTargets(t *testing.T) {
	got := Merge([]artifacts.CasePack{rich("inv-empty")}, nil)
	if len(got) != 0 {
		t.Fatalf("a pack with no target files must not survive, got %d", len(got))
	}
}

func TestMerge_RichPacksSortFirstAndOrderIsStable(t *testing.T) {
	a := Merge(
		[]artifacts.CasePack{rich("inv-1", "z.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	b := Merge(
		[]artifacts.CasePack{rich("inv-1", "z.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	if len(a) != 2 || a[0].CaseID != "inv-1" {
		t.Fatalf("rich packs must come first, got %+v", a)
	}
	for i := range a {
		if a[i].CaseID != b[i].CaseID {
			t.Fatal("ordering must be identical across runs")
		}
	}
}

func TestWrite_UsesCaseGlobFilenames(t *testing.T) {
	runDir := t.TempDir()
	if err := Write(runDir, []artifacts.CasePack{rich("inv-1", "a.c"), thin("cand-1", "low", "b.c")}); err != nil {
		t.Fatal(err)
	}
	// The exact glob every downstream stage uses.
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("want 2 files matching case-*.json, got %d: %v", len(paths), paths)
	}
	if _, err := os.Stat(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json")); err != nil {
		t.Fatalf("numbering must start at 001: %v", err)
	}
}

// target files are a set, not a list: two packs naming the same files in a
// different order, or with duplicates, must still merge.
func TestMerge_SameSetDifferentOrderAndDupesStillMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c", "z.c")},
		[]artifacts.CasePack{thin("cand-1", "high", "z.c", "a.c", "z.c")},
	)
	if len(got) != 1 {
		t.Fatalf("target files are a set, not a list: want 1 pack, got %d", len(got))
	}
}

func TestBuildFromCandidate_SetsCategoryFromKind(t *testing.T) {
	manifest := artifacts.Manifest{LocalPath: "/tmp/repo", Commit: "abcdef1234", Focus: "tee"}

	attestation := BuildFromCandidate(artifacts.Candidate{Kind: "attestation", Paths: []string{"a.c"}}, manifest, 0)
	if attestation.Category != "attestation" {
		t.Fatalf("known kind must map to itself, got %q", attestation.Category)
	}

	unknown := BuildFromCandidate(artifacts.Candidate{Kind: "something_else", Paths: []string{"a.c"}}, manifest, 1)
	if unknown.Category != "boundary" {
		t.Fatalf("unknown kind must fall back to boundary, got %q", unknown.Category)
	}

	empty := BuildFromCandidate(artifacts.Candidate{Paths: []string{"a.c"}}, manifest, 2)
	if empty.Category != "boundary" {
		t.Fatalf("empty kind must fall back to boundary, got %q", empty.Category)
	}
}

// absorb writes WhySelected onto a struct copy of base, but the slice header
// still points at the caller's backing array; if absorb appended onto it
// directly, an append with spare capacity would corrupt the caller's
// pre-merge pack in place. Build base with cap > len so an in-place append
// would succeed silently if this regressed.
func TestAbsorb_DoesNotMutateCallersBackingArray(t *testing.T) {
	backing := make([]string, 1, 4) // len 1, cap 4: room for an in-place append
	backing[0] = "why-base"
	base := rich("inv-1", "a.c")
	base.WhySelected = backing

	preMerge := base.WhySelected

	_ = Merge([]artifacts.CasePack{base}, []artifacts.CasePack{thin("cand-1", "low", "a.c")})

	if len(preMerge) != 1 || preMerge[0] != "why-base" {
		t.Fatalf("absorb must not mutate the caller's pre-merge slice, got %+v", preMerge)
	}
}

// priority strings from the model come through with no case-folding
// (planner.go copies cand.Priority verbatim), so a merge must not let an
// unnormalized-but-recognisable value like "High" lose to a lowercase one.
func TestMerge_UnnormalizedPriorityStillWins(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c")}, // priority "medium"
		[]artifacts.CasePack{thin("cand-1", "High", "a.c")},
	)
	if len(got) != 1 {
		t.Fatalf("want 1 merged pack, got %d", len(got))
	}
	if got[0].Priority != "High" {
		t.Fatalf(`"High" must beat "medium" once normalized for comparison, got %q`, got[0].Priority)
	}
}

// ─── DedupePacks (across --samples passes) ───────────────────────────

// withTWEs marks a pack as carrying playbook knowledge, which is what
// DedupePacks sorts on.
func withTWEs(p artifacts.CasePack, ids ...string) artifacts.CasePack {
	p.RelatedTWEs = ids
	return p
}

// The C1 regression in one test: pass 1 and pass 2 both surface the same
// file. Merge cannot collapse them — it only folds thin into rich, and these
// are two separate Run results — so DedupePacks must.
func TestDedupePacks_SameTargetSetAcrossPassesCollapses(t *testing.T) {
	pass1 := thin("cand-1", "low", "a.c")
	pass2 := thin("cand-2", "high", "a.c")

	got := DedupePacks([]artifacts.CasePack{pass1, pass2})
	if len(got) != 1 {
		t.Fatalf("the same target set seen in two passes is one finding, got %d packs", len(got))
	}
	if got[0].CaseID != "cand-1" {
		t.Errorf("first occurrence must win the slot, got %q", got[0].CaseID)
	}
	if got[0].Priority != "high" {
		t.Errorf("the duplicate must be absorbed (higher priority wins), got %q", got[0].Priority)
	}
	if len(got[0].WhySelected) != 2 {
		t.Errorf("WhySelected must be the union of both, got %v", got[0].WhySelected)
	}
}

// fullyLoaded builds a rich pack with EVERY investigation-derived field
// populated, each value prefixed with the pack's id so a collapse that keeps
// only one side's values is visible field by field.
func fullyLoaded(id, twe string, files ...string) artifacts.CasePack {
	return artifacts.CasePack{
		SchemaVersion:        "teecheck.case_pack.v1",
		CaseID:               id,
		Category:             "standard",
		Priority:             "medium",
		TargetFiles:          files,
		TargetSymbols:        []string{id + "-sym"},
		WhySelected:          []string{id + "-why"},
		RelatedTWEs:          []string{twe},
		RelatedInvariants:    []string{id + "-inv"},
		ArchitectureRefs:     []string{id + "-arch"},
		ToolFactRefs:         []string{id + "-fact"},
		RequiredEvidence:     []string{id + "-ev"},
		MissingLinks:         []string{id + "-link"},
		CommonDefenses:       []string{id + "-def"},
		CommonFalsePositives: []string{id + "-fp"},
		CoverageGaps:         []string{id + "-gap"},
	}
}

// knowledgeFields is the set a collapse must never shrink, keyed for
// error messages. Keep in sync with absorb's union list in casepacks.go.
// RelatedTWEs is excluded only because its values are real playbook IDs
// rather than id-prefixed fixtures; every test below asserts it directly.
func knowledgeFields(p artifacts.CasePack) map[string][]string {
	return map[string][]string{
		"target_symbols":         p.TargetSymbols,
		"why_selected":           p.WhySelected,
		"related_invariants":     p.RelatedInvariants,
		"architecture_refs":      p.ArchitectureRefs,
		"tool_fact_refs":         p.ToolFactRefs,
		"required_evidence":      p.RequiredEvidence,
		"missing_links":          p.MissingLinks,
		"common_defenses":        p.CommonDefenses,
		"common_false_positives": p.CommonFalsePositives,
		"coverage_gaps":          p.CoverageGaps,
	}
}

func assertContainsAll(t *testing.T, got artifacts.CasePack, wantSubstrings ...string) {
	t.Helper()
	for name, values := range knowledgeFields(got) {
		for _, want := range wantSubstrings {
			if !containsAny(values, want) {
				t.Errorf("%s = %v: nothing from %q survived the collapse — this is the PR-06 data loss again",
					name, values, want)
			}
		}
	}
}

func containsAny(values []string, prefix string) bool {
	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

// Two rich packs sharing a target set survive Merge (it only folds thin into
// rich) but must collapse in DedupePacks — and the collapse must be
// LOSSLESS. These are two different TWE scenarios about the same file: with
// absorb taking every field but WhySelected/Priority from its base, the
// second investigation's entire playbook payload — its common_defenses, its
// common_false_positives, its required_evidence — vanished before any agent
// could read it, which is the exact bug this branch exists to fix.
//
// Reachable with --samples 1: two done.investigations entries whose
// filled_roles resolve to the same file collide inside a single pass.
func TestDedupePacks_TwoRichPacksWithSameTargetSetCollapse(t *testing.T) {
	got := DedupePacks([]artifacts.CasePack{
		fullyLoaded("inv-1", "TWE-FLOW-001", "a.c"),
		fullyLoaded("inv-2", "TWE-GUARD-004", "a.c"),
	})
	if len(got) != 1 {
		t.Fatalf("want 1 pack, got %d", len(got))
	}
	if got[0].CaseID != "inv-1" {
		t.Errorf("with both sides rich, the first occurrence keeps the identity, got %q", got[0].CaseID)
	}
	if got[0].Category != "standard" {
		t.Errorf("Category must come from the same pack as CaseID, got %q", got[0].Category)
	}
	// Both sides' knowledge, not just the survivor's identity.
	assertContainsAll(t, got[0], "inv-1", "inv-2")
	if len(got[0].RelatedTWEs) != 2 ||
		!containsAny(got[0].RelatedTWEs, "TWE-FLOW-001") ||
		!containsAny(got[0].RelatedTWEs, "TWE-GUARD-004") {
		t.Errorf("related_twes = %v, want both playbooks", got[0].RelatedTWEs)
	}
}

// The --samples > 1 ordering the measurement runs actually produce:
// allPacks arrives as pass1-rich, pass1-thin, pass2-rich, pass2-thin, so a
// pass-1 THIN pack reaches DedupePacks before a pass-2 RICH pack with the
// same target set and takes the first-occurrence slot. absorb must be
// richness-aware, not position-aware: if the thin pack won by virtue of
// arriving first, every playbook field would be empty on disk.
func TestDedupePacks_ThinFirstThenRichKeepsTheRichPacksKnowledge(t *testing.T) {
	got := DedupePacks([]artifacts.CasePack{
		thin("cand-1", "high", "a.c"),
		fullyLoaded("inv-1", "TWE-FLOW-001", "a.c"),
	})
	if len(got) != 1 {
		t.Fatalf("want 1 pack, got %d", len(got))
	}
	if got[0].CaseID != "inv-1" {
		t.Errorf("the knowledge-bearing pack must supply the identity (its CaseID is the "+
			"InvestigationID that ties the pack to 03_investigations/), got %q", got[0].CaseID)
	}
	if got[0].Category != "standard" {
		t.Errorf("Category must come from the same pack as CaseID, got %q", got[0].Category)
	}
	assertContainsAll(t, got[0], "inv-1")
	if !containsAny(got[0].RelatedTWEs, "TWE-FLOW-001") {
		t.Errorf("related_twes = %v, want the rich pack's playbook", got[0].RelatedTWEs)
	}
	if !containsAny(got[0].WhySelected, "why-cand-1") {
		t.Errorf("the thin pack's why_selected must still be absorbed, got %v", got[0].WhySelected)
	}
	if got[0].Priority != "high" {
		t.Errorf("the higher priority must still win regardless of which side is rich, got %q", got[0].Priority)
	}
}

// A pack from an investigation with no twe_ids still carries real evidence.
// If richness were keyed on RelatedTWEs alone it would sort into the thin
// group and be truncated first by --max-cases.
func TestDedupePacks_RichWithoutTWEsStillSortsFirst(t *testing.T) {
	noTWEs := fullyLoaded("inv-1", "", "b.c")
	noTWEs.RelatedTWEs = nil
	got := DedupePacks([]artifacts.CasePack{
		thin("cand-1", "low", "a.c"),
		noTWEs,
	})
	if len(got) != 2 {
		t.Fatalf("want 2 packs, got %d", len(got))
	}
	if got[0].CaseID != "inv-1" {
		t.Errorf("a pack with required_evidence/coverage_gaps but no related_twes is still the "+
			"most informative thing in the run and must not be truncated first, order = %v", caseIDs(got))
	}
}

func TestDedupePacks_DifferentTargetSetsAreKept(t *testing.T) {
	got := DedupePacks([]artifacts.CasePack{
		thin("cand-1", "low", "a.c"),
		thin("cand-2", "low", "b.c"),
		// A partial overlap is a different set and must not collapse —
		// same rule Merge enforces.
		thin("cand-3", "low", "a.c", "b.c"),
	})
	if len(got) != 3 {
		t.Fatalf("want 3 distinct packs, got %d: %+v", len(got), got)
	}
}

// --max-cases truncates the tail, so the tail must be the least informative
// packs: the ones with no playbook knowledge behind them.
func TestDedupePacks_PlaybookPacksSortBeforeThinOnes(t *testing.T) {
	got := DedupePacks([]artifacts.CasePack{
		thin("cand-1", "low", "a.c"),
		withTWEs(rich("inv-1", "b.c"), "TWE-STATE-001"),
		thin("cand-2", "low", "c.c"),
		withTWEs(rich("inv-2", "d.c"), "TWE-ATT-001"),
	})
	wantOrder := []string{"inv-1", "inv-2", "cand-1", "cand-2"}
	if len(got) != len(wantOrder) {
		t.Fatalf("want %d packs, got %d", len(wantOrder), len(got))
	}
	for i, want := range wantOrder {
		if got[i].CaseID != want {
			t.Fatalf("order = %v, want %v (playbook packs first, relative order preserved within each group)",
				caseIDs(got), wantOrder)
		}
	}
}

func TestDedupePacks_DropsEmptyTargets(t *testing.T) {
	got := DedupePacks([]artifacts.CasePack{
		rich("inv-empty"),
		thin("cand-1", "low", "a.c"),
	})
	if len(got) != 1 || got[0].CaseID != "cand-1" {
		t.Fatalf("a pack with no target files must not survive, got %+v", caseIDs(got))
	}
}

func TestDedupePacks_OrderIsDeterministicAcrossCalls(t *testing.T) {
	in := []artifacts.CasePack{
		thin("cand-1", "low", "z.c"),
		withTWEs(rich("inv-1", "a.c"), "TWE-STATE-001"),
		thin("cand-2", "high", "z.c"),
		thin("cand-3", "low", "m.c"),
	}
	a := DedupePacks(in)
	b := DedupePacks(in)
	if len(a) != len(b) {
		t.Fatalf("length differs between identical calls: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].CaseID != b[i].CaseID {
			t.Fatalf("ordering must be identical across calls: %v vs %v", caseIDs(a), caseIDs(b))
		}
	}
}

// DedupePacks must not corrupt its input: the pipeline logs the pre-dedupe
// count and the caller's slice is still live after the call.
func TestDedupePacks_DoesNotMutateInput(t *testing.T) {
	in := []artifacts.CasePack{
		thin("cand-1", "low", "a.c"),
		thin("cand-2", "high", "a.c"),
	}
	_ = DedupePacks(in)
	if in[0].Priority != "low" || len(in[0].WhySelected) != 1 {
		t.Fatalf("input pack was mutated: %+v", in[0])
	}
}

func caseIDs(packs []artifacts.CasePack) []string {
	out := make([]string, 0, len(packs))
	for _, p := range packs {
		out = append(out, p.CaseID)
	}
	return out
}

func TestBuildFromCandidate_CarriesPathsAndWhySelected(t *testing.T) {
	cand := artifacts.Candidate{
		Paths:       []string{"src/a.c"},
		Symbols:     []string{"f"},
		Priority:    "high",
		WhySelected: []string{"reached from an untrusted entrypoint"},
	}
	pack := BuildFromCandidate(cand, artifacts.Manifest{LocalPath: "/tmp/repo", Commit: "abcdef1234", Focus: "tee"}, 0)
	if len(pack.TargetFiles) != 1 || pack.TargetFiles[0] != "src/a.c" {
		t.Fatalf("target files not carried: %+v", pack.TargetFiles)
	}
	if len(pack.WhySelected) == 0 {
		t.Fatal("why_selected not carried")
	}
	if pack.CaseID == "" {
		t.Fatal("a thin pack still needs a CaseID")
	}
}
