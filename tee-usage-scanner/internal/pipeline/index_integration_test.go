package pipeline_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// linkQueryPack makes codeql/index/cpp resolvable from a temporary
// knowledge root.
func linkQueryPack(t *testing.T, knowledgeRoot string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	link := filepath.Join(filepath.Dir(knowledgeRoot), "codeql")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(repoRoot, "codeql"), link); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
}

// pinnedOrigin builds a local git repository with a little C in it and
// returns its path and HEAD, so a run can be pinned to a real revision
// without a network.
func pinnedOrigin(t *testing.T) (origin, commit string) {
	t.Helper()
	origin = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")
	for rel, body := range map[string]string{
		"README.md":       "# Pinned probe\n\nA repository the index can actually extract.\n",
		"Makefile":        "all:\n",
		"core/loader.c":   "static int helper(int v) { return v + 1; }\nint load(void) { return helper(1); }\n",
		"core/dispatch.c": "struct ops { int (*load)(void); };\nint dispatch(struct ops *o) { return o->load(); }\n",
	} {
		p := filepath.Join(origin, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	run("commit", "--quiet", "-m", "init")

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = origin
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return origin, strings.TrimSpace(string(out))
}

// A run against a real pinned revision, so the database is genuinely built
// and its attribution can be checked rather than assumed.
//
// The probe in provenance_events_test.go has no pinned repository, so its
// "not the planner" assertion passes vacuously — nothing is built at all.
// This is the one that exercises it.
func TestPipeline_IndexBuildsUnderTheIndexAgentNotThePlanner(t *testing.T) {
	if _, err := exec.LookPath("codeql"); err != nil {
		t.Skip("codeql not on PATH")
	}
	origin, commit := pinnedOrigin(t)

	cfg := probeConfig(t, "llm")
	cfg.Target = origin
	cfg.RepoURL = origin
	cfg.Commit = commit
	// The index query pack is resolved as a sibling of the knowledge root,
	// the same convention the TrustIR pack uses. probeConfig puts the
	// knowledge root in a temp dir for isolation, so link the real pack
	// beside it rather than pointing the run at the repository's own
	// knowledge directory and writing into it.
	linkQueryPack(t, cfg.KnowledgeRoot)

	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}
	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	byAgent := map[string]int{}
	for _, e := range readEvents(t, runDir) {
		if e.Type == events.TypeToolCallStarted && e.ToolName == "codeql-database-create" {
			byAgent[e.Agent]++
		}
	}
	if n := byAgent["planner-001"]; n != 0 {
		t.Errorf("the planner built the database %d time(s) — 91 seconds of its own budget on a real repository", n)
	}
	if n := byAgent["repo-index"]; n != 1 {
		t.Errorf("repo-index built the database %d time(s), want exactly 1 (agents seen: %v)", n, byAgent)
	}

	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		t.Fatal(err)
	}
	if facts.Capabilities.Symbols != artifacts.CapabilityAvailable {
		t.Fatalf("symbols = %q, want available on a repository CodeQL can extract (note: %s)",
			facts.Capabilities.Symbols, facts.IndexNote)
	}
	if len(facts.Capsules) == 0 {
		t.Error("no capsules from a repository with three functions")
	}
	if facts.TotalCallSites != facts.ResolvedCallSites+len(facts.UnresolvedCallSites) {
		t.Errorf("total %d != resolved %d + unresolved %d",
			facts.TotalCallSites, facts.ResolvedCallSites, len(facts.UnresolvedCallSites))
	}
	// dispatch() calls only through a function pointer, so the tree has one.
	if len(facts.UnresolvedCallSites) == 0 {
		t.Error("the function-pointer call must appear in the unresolved list")
	}

	var m artifacts.ProjectMap
	if err := runfs.ReadJSON(runfs.ProjectMapPath(runDir), &m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Repository.DocumentedPurpose, "index can actually extract") {
		t.Errorf("documented purpose = %q, want the README's own words", m.Repository.DocumentedPurpose)
	}
	if len(m.FunctionPages) == 0 {
		t.Error("no function card pages were written")
	}
	for _, ref := range m.FunctionPages {
		if _, err := os.Stat(filepath.Join(runDir, filepath.FromSlash(ref.Path))); err != nil {
			t.Errorf("page %s does not exist: %v", ref.Path, err)
		}
	}
}
