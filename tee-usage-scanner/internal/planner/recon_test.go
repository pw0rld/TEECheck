package planner

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// browse walks an indexed ReconState all the way to a satisfied gate. It is
// the "everything is fine" baseline the negative tests break one piece of.
func browse(r *ReconState) {
	r.Observe("get_repository_card", "", true)
	for m := 0; m < reconMinModules; m++ {
		r.Observe("list_functions", fmt.Sprintf("core/mod%d", m), true)
	}
	for i := 0; i < reconMinSymbols; i++ {
		r.Observe("get_function_card", fmt.Sprintf("cpp:core/mod%d/f%d.c:1:fn%d()", i%reconMinSpread, i, i), true)
	}
	r.Observe("get_callers", "cpp:core/mod0/f0.c:1:fn0()", true)
}

// Counting calls lets the model open one function five times. The gate must
// count distinct things actually seen.
func TestReconState_CountsDistinctNotRepeats(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	for i := 0; i < 10; i++ {
		r.Observe("get_function_card", "cpp:a/b/c.c:1:f()", true)
	}
	if r.DistinctSymbolsViewed() != 1 {
		t.Errorf("opening one symbol ten times counted as %d", r.DistinctSymbolsViewed())
	}
}

// A failed action observed nothing. run-b had seven consecutive ripgrep
// failures; crediting those as browsing would satisfy a gate with no
// information behind it.
func TestReconState_IgnoresFailedActions(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_function_card", "cpp:a/b/c.c:1:f()", false)
	if r.DistinctSymbolsViewed() != 0 {
		t.Error("a failed action must not count as browsing")
	}
}

// Fifteen functions from one module is not reconnaissance of a 34-module
// project. Without the spread floor the cheapest way to satisfy a count is
// to page through whatever the first list_functions returned.
func TestReconState_SpreadResistsPagingThroughOneModule(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_repository_card", "", true)
	for m := 0; m < reconMinModules; m++ {
		r.Observe("list_functions", fmt.Sprintf("core/mod%d", m), true)
	}
	r.Observe("get_callers", "cpp:core/one/a.c:1:f()", true)
	// Every capsule from the same module.
	for i := 0; i < reconMinSymbols*2; i++ {
		r.Observe("get_function_card", fmt.Sprintf("cpp:core/one/f%d.c:1:fn%d()", i, i), true)
	}
	if r.Satisfied() {
		t.Fatal("paging through one module satisfied the gate")
	}
	if !strings.Contains(r.Unmet(), "module") {
		t.Errorf("the refusal must name the spread as what is missing:\n%s", r.Unmet())
	}

	for m := 1; m < reconMinSpread; m++ {
		r.Observe("get_function_card", fmt.Sprintf("cpp:core/mod%d/x.c:1:g()", m), true)
	}
	if !r.Satisfied() {
		t.Errorf("spreading across %d modules must satisfy it:\n%s", reconMinSpread, r.Unmet())
	}
}

// find_symbols resolves a name to candidate ids. That is disambiguation,
// not a statement about how the code connects — and a gate that accepted it
// as the relation query would be satisfied by a pass that never asked how
// anything reaches anything.
func TestReconState_FindSymbolsIsNotARelationQuery(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	browse(r)
	if !r.Satisfied() {
		t.Fatalf("baseline must be satisfied:\n%s", r.Unmet())
	}

	r2 := NewReconState(ReconModeIndexed)
	r2.Observe("get_repository_card", "", true)
	for m := 0; m < reconMinModules; m++ {
		r2.Observe("list_functions", fmt.Sprintf("core/mod%d", m), true)
	}
	for i := 0; i < reconMinSymbols; i++ {
		r2.Observe("get_function_card", fmt.Sprintf("cpp:core/mod%d/f%d.c:1:fn%d()", i%reconMinSpread, i, i), true)
	}
	for i := 0; i < 10; i++ {
		r2.Observe("find_symbols", "shdr_load_pub_key", true)
	}
	if r2.Satisfied() {
		t.Error("ten find_symbols calls satisfied the relation requirement")
	}
}

// Listing the module list is orientation. If it counted, one call would
// clear the module floor and the floor would mean nothing.
func TestReconState_ListingTheModuleListIsNotReviewingModules(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	for i := 0; i < 10; i++ {
		r.Observe("list_modules", "", true)
	}
	if r.DistinctModulesViewed() != 0 {
		t.Errorf("list_modules credited %d modules as reviewed", r.DistinctModulesViewed())
	}
}

// With no index there is nothing to browse — but "nothing to browse" must
// not become "read nothing at all". The tree-only mode still requires real
// source reading.
func TestReconState_TreeOnlyStillRequiresReading(t *testing.T) {
	r := NewReconState(ReconModeTreeOnly)
	if r.Satisfied() {
		t.Fatal("tree_only must not be satisfied by default")
	}
	r.Observe("list_dir", ".", true)
	if r.Satisfied() {
		t.Error("a directory listing alone is not reconnaissance")
	}
	for i := 0; i < minTreeReads; i++ {
		r.Observe("read_file", fmt.Sprintf("core/f%d.c", i), true)
	}
	if !r.Satisfied() {
		t.Errorf("a listing plus real reads must satisfy tree_only:\n%s", r.Unmet())
	}
}

// A four-file fixture cannot open fifteen function cards. Clamping the
// floors against the repository's own totals is what keeps the gate from
// being unsatisfiable on a small tree.
func TestReconState_FloorsClampToWhatTheRepositoryHas(t *testing.T) {
	r := NewReconState(ReconModeIndexed).WithTotals(2, 3, 4)
	r.Observe("get_repository_card", "", true)
	r.Observe("list_functions", "core", true)
	r.Observe("list_functions", "lib", true)
	r.Observe("get_function_card", "cpp:core/a.c:1:f()", true)
	r.Observe("get_function_card", "cpp:lib/b.c:1:g()", true)
	r.Observe("get_function_card", "cpp:lib/c.c:1:h()", true)
	r.Observe("get_callers", "cpp:core/a.c:1:f()", true)
	if !r.Satisfied() {
		t.Errorf("a 2-module 3-function repository must be able to satisfy the gate:\n%s", r.Unmet())
	}
}

// A zero total means the project map could not say, not that the repository
// is empty. Clamping to it would satisfy the gate by knowing less — the one
// way a degraded index could make the Planner look more thorough.
func TestReconState_AnUnknownTotalDoesNotLowerTheFloor(t *testing.T) {
	r := NewReconState(ReconModeIndexed) // no totals recorded
	r.Observe("get_repository_card", "", true)
	r.Observe("get_callers", "cpp:core/a.c:1:f()", true)
	if r.Satisfied() {
		t.Error("an unknown module total satisfied the module floor")
	}
}

// The forced-done final round (planner.go's FINAL ROUND block) and the gate
// must not contradict each other: the model cannot be told both "you MUST
// call done" and "done is refused".
func TestReconState_FinalRoundOverridesTheGate(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	if !r.AllowDone(true) {
		t.Error("on the final round done must be allowed regardless of the gate")
	}
	if r.AllowDone(false) {
		t.Error("before the final round an unmet gate must still refuse done")
	}
	if r.TerminationReason(true) != terminationReconIncomplete {
		t.Errorf("a run that finished gated must be distinguishable from one that finished, got %q",
			r.TerminationReason(true))
	}
}

// Blocking only `done` lets the model open one function, raise a lead on it,
// flip to investigation and skip MAP entirely.
func TestReconState_TheGateBlocksLeadsToo(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_function_card", "cpp:core/a.c:1:f()", true)
	if r.AllowLead() {
		t.Fatal("one function card was enough to open a lead")
	}
	browse(r)
	if !r.AllowLead() {
		t.Errorf("a satisfied gate must allow a lead:\n%s", r.Unmet())
	}
}

// Neither escape may be silent. A pass released because it ran out of
// browsing rounds did not conclude for the same reason as one that finished
// looking, and the ledger has to be able to tell them apart.
func TestReconState_TheBudgetEscapeIsRecorded(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	if r.AllowLead() {
		t.Fatal("an unmet gate must block")
	}
	r.ExhaustReconBudget()
	if !r.AllowLead() {
		t.Error("an exhausted reconnaissance budget must release the gate")
	}
	if r.Status() != reconStatusBudgetExhausted {
		t.Errorf("status = %q, want the escape recorded", r.Status())
	}
	if r.TerminationReason(true) != terminationReconBudgetSpent {
		t.Errorf("termination = %q, want the escape named", r.TerminationReason(true))
	}
}

// An unindexed, unlistable repository cannot be browsed into a satisfied
// gate. Saying so is the point — the alternative is a mode that silently
// behaves like a satisfied one.
func TestReconState_UnavailableIsNeverSatisfiedByBrowsing(t *testing.T) {
	r := NewReconState(ReconModeUnavailable)
	browse(r)
	for i := 0; i < 50; i++ {
		r.Observe("read_file", fmt.Sprintf("f%d.c", i), true)
	}
	if r.Satisfied() {
		t.Error("the unavailable mode was satisfied by browsing")
	}
	if !strings.Contains(r.Unmet(), "round budget") {
		t.Errorf("the refusal must say what will release it:\n%s", r.Unmet())
	}
}

// A refusal that does not say what would lift it is a wall. Every unmet
// requirement names the action that would meet it.
func TestReconState_UnmetNamesTheActionThatWouldSatisfyIt(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	unmet := r.Unmet()
	for _, action := range []string{"get_repository_card", "list_functions", "get_function_card", "get_callers"} {
		if !strings.Contains(unmet, action) {
			t.Errorf("the refusal never names %s:\n%s", action, unmet)
		}
	}
}

// The mode comes from the index's own per-capability verdict, not from a
// guess. An unavailable symbol capability with a readable tree is tree_only;
// with nothing readable at all it is unavailable, and the two gates differ.
func TestReconModeFor_FollowsTheIndexsOwnVerdict(t *testing.T) {
	indexed := artifacts.ProjectMap{}
	indexed.Capabilities.Symbols = artifacts.CapabilityAvailable
	if got := ReconModeFor(indexed); got != ReconModeIndexed {
		t.Errorf("available symbols -> %q, want indexed", got)
	}

	partial := artifacts.ProjectMap{}
	partial.Capabilities.Symbols = artifacts.CapabilityPartial
	if got := ReconModeFor(partial); got != ReconModeIndexed {
		t.Errorf("partial symbols -> %q, want indexed — a partial index is still browsable", got)
	}

	tree := artifacts.ProjectMap{}
	tree.Capabilities.Symbols = artifacts.CapabilityUnavailable
	tree.Repository.FileCount = 12
	if got := ReconModeFor(tree); got != ReconModeTreeOnly {
		t.Errorf("no index over a readable tree -> %q, want tree_only", got)
	}

	nothing := artifacts.ProjectMap{}
	nothing.Capabilities.Symbols = artifacts.CapabilityUnavailable
	if got := ReconModeFor(nothing); got != ReconModeUnavailable {
		t.Errorf("no index and no files -> %q, want unavailable", got)
	}
}

// The key an action is recorded under comes from its own arguments. If
// get_function_card were keyed on anything but symbol_id, two different
// definitions would collapse into one observation — the same identity
// mistake SymbolID exists to prevent.
func TestReconKeyFor_ReadsTheIdentifyingArgument(t *testing.T) {
	cases := []struct {
		action, args, want string
	}{
		{"list_functions", `{"module":"core/crypto"}`, "core/crypto"},
		{"get_function_card", `{"symbol_id":"cpp:a/b.c:1:f()"}`, "cpp:a/b.c:1:f()"},
		{"get_callers", `{"symbol_id":"cpp:a/b.c:1:f()"}`, "cpp:a/b.c:1:f()"},
		{"read_file", `{"path":"core/a.c","start":1}`, "core/a.c"},
		{"find_symbols", `{"name":"f"}`, ""},
		{"read_file", `not json`, ""},
	}
	for _, c := range cases {
		if got := reconKeyFor(c.action, json.RawMessage(c.args)); got != c.want {
			t.Errorf("reconKeyFor(%s, %s) = %q, want %q", c.action, c.args, got, c.want)
		}
	}
}

// The gate's cost is measured in actions; the budget is denominated in
// rounds. Nothing but this test converts between them, and when nothing did,
// they disagreed: the indexed gate needed 22 successful actions and six
// rounds at three a round afforded 18. The gate was unsatisfiable by
// construction, so it never gated anything — it just burned six rounds and
// stepped aside. Both real runs against OP-TEE left reconnaissance through
// the escape, having landed 10 and 12 of the 22.
func TestReconBudget_CanReachTheIndexedGate(t *testing.T) {
	// One repository card, one listing per module floor, one card per symbol
	// floor, one relation query. The spread floor is carried by the cards.
	needed := 1 + reconMinModules + reconMinSymbols + 1

	b := NewDefaultBudget()
	slots := b.MaxReconRounds * DefaultActionsPerRound
	if slots < needed {
		t.Fatalf("the indexed gate needs %d successful actions and the reconnaissance "+
			"budget affords %d (%d rounds x %d actions) — the gate can never be met, "+
			"so every run leaves reconnaissance through the escape",
			needed, slots, b.MaxReconRounds, DefaultActionsPerRound)
	}

	// Slack is part of the requirement, not a bonus. A model spends rounds
	// deciding where to look next, and a round whose browsing action failed
	// buys no progress — recon-001 lost two to a truncated symbol_id.
	if slack := slots - needed; slack < DefaultActionsPerRound {
		t.Errorf("only %d spare action(s): a single failed browse or one round "+
			"spent thinking puts the gate out of reach again", slack)
	}
}

// The tree-only gate is cheaper but has the same shape, and nothing else
// checks it either.
func TestReconBudget_CanReachTheTreeOnlyGate(t *testing.T) {
	needed := 1 + minTreeReads // one list_dir on the root, then real reads
	b := NewDefaultBudget()
	if slots := b.MaxReconRounds * DefaultActionsPerRound; slots < needed {
		t.Fatalf("the tree_only gate needs %d actions, budget affords %d", needed, slots)
	}
}

// runs/recon-003 raised a lead naming the real defect and it was refused.
// The Planner had resolved both symbols with find_symbols and read
// core/kernel/ree_fs_ta.c across the call, but neither had been opened as a
// card — and SawSymbol accepted only cards. The rule had confused how a
// function was observed with whether it was.
func TestReconState_ReadingASymbolsSourceCountsAsSeeingIt(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	const id = artifacts.SymbolID("cpp:core/kernel/ree_fs_ta.c:314:check_update_version(const char * db, uint32_t v)")

	if r.SawSymbol(id) {
		t.Fatal("nothing has been observed yet")
	}
	r.ObserveAction("read_file",
		json.RawMessage(`{"path":"core/kernel/ree_fs_ta.c","start":300,"end":370}`), true)
	if !r.SawSymbol(id) {
		t.Error("a read spanning the definition's line is a stronger observation than its card")
	}
}

// The span has to contain the line. Reading elsewhere in the same file says
// nothing about a definition further down.
func TestReconState_AReadThatMissesTheLineIsNotSeeingIt(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	const id = artifacts.SymbolID("cpp:core/kernel/ree_fs_ta.c:314:check_update_version()")

	r.ObserveAction("read_file",
		json.RawMessage(`{"path":"core/kernel/ree_fs_ta.c","start":1,"end":80}`), true)
	if r.SawSymbol(id) {
		t.Error("lines 1-80 do not show a function defined at 314")
	}
	// A different file entirely, covering the same line numbers.
	r.ObserveAction("read_file",
		json.RawMessage(`{"path":"core/tee/fs_htree.c","start":300,"end":370}`), true)
	if r.SawSymbol(id) {
		t.Error("the same line range in another file is not this definition")
	}
}

// A read with no end reads to the handler's own cap, and the target may sit
// anywhere in the span that actually arrived.
func TestReconState_AnOpenEndedReadCoversTheHandlersCap(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.ObserveAction("read_file", json.RawMessage(`{"path":"a.c","start":100}`), true)

	if !r.SawSymbol("cpp:a.c:400:f()") {
		t.Error("an open-ended read from 100 covers line 400")
	}
	if r.SawSymbol("cpp:a.c:700:g()") {
		t.Errorf("it must not claim to cover line 700 — the cap is %d lines", readFileLineCap)
	}
}

// find_symbols resolves a name to candidate ids without showing any code. A
// lead grounded on it alone would be a question about a name, which is what
// this check exists to refuse.
func TestReconState_FindSymbolsAloneIsNotSeeingASymbol(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.ObserveAction("find_symbols", json.RawMessage(`{"name":"check_update_version"}`), true)
	if r.SawSymbol("cpp:core/kernel/ree_fs_ta.c:314:check_update_version()") {
		t.Error("resolving a name is not looking at the code behind it")
	}
}

// A failed read observed nothing.
func TestReconState_AFailedReadGroundsNothing(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.ObserveAction("read_file",
		json.RawMessage(`{"path":"core/kernel/ree_fs_ta.c","start":300,"end":370}`), false)
	if r.SawSymbol("cpp:core/kernel/ree_fs_ta.c:314:f()") {
		t.Error("a read that failed shows nothing")
	}
}
