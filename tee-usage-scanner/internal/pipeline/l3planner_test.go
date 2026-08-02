package pipeline

// Internal (package pipeline) test: runL3Planner is unexported and is the
// smallest seam that exercises the --samples pass loop together with the
// once-per-run Case Pack persistence. Driving pipeline.RunWithClient instead
// would drag in preprocess, architecture, invariants and the whole four-agent
// chain, none of which bear on what is under test here.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// donePass builds one planner round response whose single action is `done`
// with the given candidates. Each candidate names exactly one file.
func donePass(t *testing.T, files ...string) string {
	t.Helper()
	cands := make([]map[string]any, 0, len(files))
	for _, f := range files {
		cands = append(cands, map[string]any{
			"id":           f,
			"kind":         "attestation",
			"priority":     "high",
			"paths":        []string{f},
			"symbols":      []string{"sym"},
			"why_selected": []string{"why-" + f},
			"confidence":   0.8,
		})
	}
	data, err := json.Marshal(map[string]any{
		"thought": "done",
		"actions": []map[string]any{{
			"name": "done",
			"args": map[string]any{"summary": "s", "candidates": cands, "investigations": []any{}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// setupPlannerRun creates the repo fixture and the run-dir artifacts
// runL3Planner reads before it starts planning (00_manifest.json and the
// project profile).
func setupPlannerRun(t *testing.T, repoFiles ...string) (repoRoot, runDir string) {
	t.Helper()
	repoRoot = t.TempDir()
	runDir = t.TempDir()
	for _, rel := range repoFiles {
		full := filepath.Join(repoRoot, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("int f(void) { return 0; }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "multi-sample-test",
		RepoURL:       "https://example.invalid/repo",
		LocalPath:     repoRoot,
		Commit:        "abcdef1234567",
		Focus:         "tee",
	}); err != nil {
		t.Fatal(err)
	}
	return repoRoot, runDir
}

// readWrittenPacks reads 03_cases/case-*.json back through the exact glob
// every downstream stage uses, and asserts the numbering is contiguous from
// 001 — an orphan left by an earlier pass would still match the glob, so the
// numbering check alone is not enough and the caller also inspects contents.
func readWrittenPacks(t *testing.T, runDir string) []artifacts.CasePack {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	packs := make([]artifacts.CasePack, 0, len(paths))
	for i, p := range paths {
		want := filepath.Join(runfs.CasePacksDir(runDir), fmt.Sprintf("case-%03d.json", i+1))
		if p != want {
			t.Fatalf("case pack numbering must be contiguous from 001: got %v", paths)
		}
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err != nil {
			t.Fatal(err)
		}
		packs = append(packs, pack)
	}
	return packs
}

func targetFilesOf(packs []artifacts.CasePack) []string {
	var out []string
	for _, p := range packs {
		out = append(out, p.TargetFiles...)
	}
	sort.Strings(out)
	return out
}

// The C1 regression, end to end. planner.Run used to call planner.Write on
// every --samples pass, restarting the case-%03d numbering each time: with
// pass 1 emitting three candidates and pass 2 emitting one, 03_cases/ ended
// up holding pass 2's case-001 next to pass 1's orphaned case-002/003 — an
// arbitrary splice that silently lost pass 1's first finding. Persistence now
// happens once, after the loop, on the deduped union of every pass.
func TestRunL3Planner_MultiSample_WritesDedupedUnionOnce(t *testing.T) {
	repoRoot, runDir := setupPlannerRun(t, "src/a.c", "src/b.c", "src/c.c", "src/d.c")

	client := &llmtest.FakeClient{
		Responses: []string{
			// pass 1: three candidates
			donePass(t, "src/a.c", "src/b.c", "src/c.c"),
			// pass 2: one candidate already seen, one new
			donePass(t, "src/b.c", "src/d.c"),
		},
		Default: donePass(t),
	}

	cfg := config.Config{
		Focus:         "tee",
		RunDir:        runDir,
		KnowledgeRoot: t.TempDir(),
		Samples:       2,
	}
	if err := runL3Planner(cfg, client, repoRoot, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatalf("runL3Planner: %v", err)
	}

	packs := readWrittenPacks(t, runDir)
	got := targetFilesOf(packs)
	want := []string{"src/a.c", "src/b.c", "src/c.c", "src/d.c"}
	if len(got) != len(want) {
		t.Fatalf("03_cases/ must hold the deduped union of both passes, got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("03_cases/ must hold the deduped union of both passes, got %v want %v", got, want)
		}
	}
	// src/b.c appeared in both passes and must occupy exactly one slot.
	if len(packs) != 4 {
		t.Fatalf("want 4 packs (b.c deduped across passes), got %d", len(packs))
	}
}

// --max-cases became inert when the cap moved out of internal/cases and
// nothing replaced it (I3). It is applied after dedupe, so duplicates never
// consume a slot.
func TestRunL3Planner_MaxCasesCapsWrittenPacks(t *testing.T) {
	repoRoot, runDir := setupPlannerRun(t, "src/a.c", "src/b.c", "src/c.c", "src/d.c")

	client := &llmtest.FakeClient{
		Responses: []string{
			donePass(t, "src/a.c", "src/b.c", "src/c.c"),
			donePass(t, "src/b.c", "src/d.c"),
		},
		Default: donePass(t),
	}

	cfg := config.Config{
		Focus:         "tee",
		RunDir:        runDir,
		KnowledgeRoot: t.TempDir(),
		Samples:       2,
		MaxCases:      2,
	}
	if err := runL3Planner(cfg, client, repoRoot, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatalf("runL3Planner: %v", err)
	}

	packs := readWrittenPacks(t, runDir)
	if len(packs) != 2 {
		t.Fatalf("--max-cases=2 must cap 03_cases/ at 2 packs, got %d: %v", len(packs), targetFilesOf(packs))
	}
	// The cap truncates the tail, so the first two of the deduped union
	// survive — b.c must not have consumed a slot twice.
	if packs[0].TargetFiles[0] != "src/a.c" || packs[1].TargetFiles[0] != "src/b.c" {
		t.Fatalf("cap must drop the tail of the deduped union, got %v", targetFilesOf(packs))
	}
}

// A single-sample run is the common case and must still write every pack.
func TestRunL3Planner_SingleSampleWritesAllPacks(t *testing.T) {
	repoRoot, runDir := setupPlannerRun(t, "src/a.c", "src/b.c")

	client := &llmtest.FakeClient{
		Responses: []string{donePass(t, "src/a.c", "src/b.c")},
		Default:   donePass(t),
	}
	cfg := config.Config{Focus: "tee", RunDir: runDir, KnowledgeRoot: t.TempDir(), Samples: 1, MaxCases: 12}
	if err := runL3Planner(cfg, client, repoRoot, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatalf("runL3Planner: %v", err)
	}
	if packs := readWrittenPacks(t, runDir); len(packs) != 2 {
		t.Fatalf("want 2 packs, got %d", len(packs))
	}
}

// A Write failure must abort the run rather than being recorded and dropped
// (I2). Making 03_cases/ a regular file is the cheapest way to force it.
func TestRunL3Planner_WriteFailureAbortsTheRun(t *testing.T) {
	repoRoot, runDir := setupPlannerRun(t, "src/a.c")

	// Occupy the 03_cases path with a file so the directory cannot be
	// created under it.
	if err := os.WriteFile(runfs.CasePacksDir(runDir), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	client := &llmtest.FakeClient{
		Responses: []string{donePass(t, "src/a.c")},
		Default:   donePass(t),
	}
	cfg := config.Config{Focus: "tee", RunDir: runDir, KnowledgeRoot: t.TempDir(), Samples: 1}
	if err := runL3Planner(cfg, client, repoRoot, runDir, events.Nop{}, nil, nil); err == nil {
		t.Fatal("a failure to persist case packs must abort the run, not be swallowed into bundle.Errors")
	}
}
