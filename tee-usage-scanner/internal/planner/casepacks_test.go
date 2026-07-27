package planner

import (
	"os"
	"path/filepath"
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
