package repoindex

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// The whole stage against a real database. The canned-table tests cover the
// capability accounting and the degradation paths; this one is the only
// thing that proves the query columns the decoder indexes by are the columns
// the queries actually return — a mismatch there produces a plausible,
// empty, wrong index.
func TestRun_LiveAgainstTheFixture(t *testing.T) {
	db := fixtureDatabase(t)
	root := repoRoot(t)
	cfg := probeRun(t, "https://example.invalid/fixture", "fixture-commit")
	cfg.KnowledgeRoot = filepath.Join(root, "knowledge")

	if err := Run(cfg, readyDB{path: db}, codeql.New()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts := readFacts(t, cfg.RunDir)
	t.Logf("symbols=%d capsules=%d edges=%d unresolved=%d total=%d resolved=%d note=%q",
		len(facts.Symbols), len(facts.Capsules), len(facts.CallEdges),
		len(facts.UnresolvedCallSites), facts.TotalCallSites, facts.ResolvedCallSites, facts.IndexNote)

	if facts.TotalCallSites != facts.ResolvedCallSites+len(facts.UnresolvedCallSites) {
		t.Errorf("total %d != resolved %d + unresolved %d",
			facts.TotalCallSites, facts.ResolvedCallSites, len(facts.UnresolvedCallSites))
	}
	byName := map[string]artifacts.FunctionCapsule{}
	for _, c := range facts.Capsules {
		byName[c.Name+"@"+c.File] = c
	}
	fill := byName["fill_version@core/dispatch.c"]
	if len(fill.FieldAccesses) != 2 || len(fill.DirectFieldWrites) != 0 {
		t.Errorf("fill_version accesses=%v writes=%v — memcpy must show as access-without-write",
			fill.FieldAccesses, fill.DirectFieldWrites)
	}
	load := byName["load_pub_key@core/loader.c"]
	if len(load.DirectFieldWrites) != 1 {
		t.Errorf("load_pub_key writes=%v, want exactly one", load.DirectFieldWrites)
	}
	if len(load.Calls) != 1 {
		t.Errorf("load_pub_key calls=%v, want the one resolved edge", load.Calls)
	}
}
