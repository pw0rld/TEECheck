package planner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/projectmap"
)

// ReconMode is how much of this repository the Planner can actually browse.
// It is decided once, from the program index's own capability report, and it
// selects which completion gate applies.
type ReconMode string

const (
	// ReconModeIndexed — the program index answered. Modules, function
	// capsules and resolved call edges are all browsable.
	ReconModeIndexed ReconMode = "indexed"
	// ReconModeTreeOnly — no index, but the tree is readable. There is
	// nothing to browse, which must not become "read nothing at all".
	ReconModeTreeOnly ReconMode = "tree_only"
	// ReconModeUnavailable — neither. No amount of browsing satisfies this
	// gate; only the final round or an exhausted reconnaissance budget
	// releases it, and both are recorded.
	ReconModeUnavailable ReconMode = "unavailable"
)

// Planner phases. Narrative only — they are deliberately absent from
// MakeObservationRef, because one --samples pass walks through both.
const (
	PhaseReconnaissance = "reconnaissance"
	PhaseInvestigation  = "investigation"
)

// How a pass left reconnaissance. A run that finished gated must stay
// distinguishable from one that finished.
const (
	reconStatusSatisfied        = "satisfied"
	reconStatusBudgetExhausted  = "recon_budget_exhausted"
	reconStatusIncomplete       = "incomplete"
	reconStatusNotRequested     = "not_requested"
	terminationReconIncomplete  = "recon_incomplete"
	terminationReconBudgetSpent = "recon_budget_exhausted"
)

// The indexed gate's floors.
//
// These are floors against "concluded without reading", not coverage
// targets. OP-TEE's index holds 11,603 function definitions across 34
// modules; no browsing quota anyone would pay for approaches coverage, and
// pretending otherwise would make the numbers a target to game rather than
// a minimum to clear.
//
// Each is clamped against the repository's actual total (see clamp), so a
// four-file fixture is not held to a floor it cannot reach.
const (
	// reconMinModules — the project has more than one part, and the gate
	// should not be satisfiable from whichever one the first listing named.
	reconMinModules = 3
	// reconMinSymbols — six function capsules provide a small cross-module sample,
	// enough that the Planner has seen what this project's code looks like
	// rather than one function's neighbourhood.
	reconMinSymbols = 6
	// reconMinSpread — the requirement that resists gaming. Six
	// functions from one module is not reconnaissance of a 34-module
	// project, and without a spread floor the cheapest way to satisfy a
	// count is to page through whatever the first list_functions returned.
	reconMinSpread = 2
	// minTreeReads — with no index, real source reading is the only
	// evidence that anything was looked at. A directory listing is not.
	minTreeReads = 5
)

// ReconState is the reconnaissance gate for one --samples pass.
//
// It holds sets rather than counters. Counting calls lets the model open one
// function five times and call it five functions; on run-b seven consecutive
// ripgrep calls failed in a row, and crediting those as browsing would have
// satisfied any counter with no information behind it.
type ReconState struct {
	Mode  ReconMode
	phase string

	// Totals from the project map, used only to clamp the floors. Zero
	// means the map could not say — not that the repository is empty.
	modulesTotal   int
	functionsTotal int
	filesTotal     int

	repositoryCardRead bool
	rootListed         bool
	relationQueries    int

	modulesViewed map[string]bool
	symbolsViewed map[string]bool
	// symbolSpread is the modules the viewed symbols belong to, which is
	// not the same set as modulesViewed: listing a module's functions is
	// not opening one.
	symbolSpread map[string]bool
	filesRead    map[string]bool
	// linesRead is which line ranges of which files were actually read.
	// SawSymbol consults it, because reading a function's source is a
	// stronger observation than opening its index card, and holding a lead
	// to the card alone rejected a correct one.
	linesRead map[string][]lineRange
	// Entry reads have their own accounting: a tool may have returned source
	// before a subsequent model request actually included it. The runtime
	// credits that presented source through ObserveEntrySourceOutput.
	entryCapability string
	entrySurfaces   map[artifacts.SymbolID]artifacts.EntrySurface
	entryLinesRead  map[string]map[int]bool

	budgetExhausted bool
	skipped         bool
	leadsOpened     int
}

// NewReconState starts a pass in reconnaissance under the given mode.
func NewReconState(mode ReconMode) *ReconState {
	return &ReconState{
		Mode:          mode,
		phase:         PhaseReconnaissance,
		modulesViewed: map[string]bool{},
		symbolsViewed: map[string]bool{},
		symbolSpread:  map[string]bool{},
		filesRead:     map[string]bool{},
		linesRead:     map[string][]lineRange{},
	}
}

// ReconModeFor reads the mode off the project map's capability report.
//
// The index reports per capability rather than one verdict, so this asks the
// one question the gate depends on: can symbols be browsed at all.
func ReconModeFor(m artifacts.ProjectMap) ReconMode {
	switch m.Capabilities.Symbols {
	case artifacts.CapabilityAvailable, artifacts.CapabilityPartial:
		return ReconModeIndexed
	}
	if m.Repository.FileCount > 0 {
		return ReconModeTreeOnly
	}
	return ReconModeUnavailable
}

// WithTotals records what the project map says the repository holds, so the
// floors can be clamped against it.
func (r *ReconState) WithTotals(modules, functions, files int) *ReconState {
	r.modulesTotal, r.functionsTotal, r.filesTotal = modules, functions, files
	return r
}

// Phase is reconnaissance until a lead opens, investigation after.
func (r *ReconState) Phase() string { return r.phase }

// Observe records one completed action.
//
// key is the thing the action was about — a module path, a symbol id, a file
// path — and is what makes the record distinct. A failed action observed
// nothing and is ignored entirely: it is not a smaller observation, it is
// the absence of one.
func (r *ReconState) Observe(action, key string, ok bool) {
	if !ok {
		return
	}
	switch action {
	case "get_repository_card":
		r.repositoryCardRead = true
	case "list_modules":
		// Reading the list of modules is orientation, not module review.
		// Crediting it would satisfy the module floor in a single call.
	case "list_functions":
		if key != "" {
			r.modulesViewed[key] = true
		}
	case "get_function_card":
		if key != "" {
			r.symbolsViewed[key] = true
			if mod := moduleOfSymbolID(key); mod != "" {
				r.symbolSpread[mod] = true
			}
		}
	case "get_callers", "list_boundary_closures", "get_struct_flows":
		// Structural connection queries across call edges, 3-hop entry closures,
		// or cross-function struct-field producer/consumer links.
		r.relationQueries++
		if action == "list_boundary_closures" && key != "" {
			r.modulesViewed[key] = true
		}
	case "list_dir":
		if key == "" || key == "." || key == "/" {
			r.rootListed = true
		}
	case "read_file", "tree_sitter_outline":
		if key != "" {
			r.filesRead[key] = true
		}
	}
}

// ObserveAction pulls the key out of an action's arguments and records it.
// Unparseable args record nothing rather than an empty key.
func (r *ReconState) ObserveAction(action string, args json.RawMessage, ok bool) {
	r.Observe(action, reconKeyFor(action, args), ok)
	if ok && action == "read_file" {
		r.recordRead(args)
	}
}

// lineRange is one span of a file that was read, 1-indexed and inclusive.
type lineRange struct{ start, end int }

// readFileLineCap mirrors the read_file handler's own cap. A request with no
// end reads that many lines from the start, and a lead's target may sit
// anywhere inside the span that actually arrived — so the span has to be
// reconstructed the same way the handler computes it.
const readFileLineCap = 500

// recordRead remembers which lines of which file a successful read covered.
func (r *ReconState) recordRead(args json.RawMessage) {
	var a struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
	}
	if len(args) == 0 || json.Unmarshal(args, &a) != nil || a.Path == "" {
		return
	}
	if a.Start <= 0 {
		a.Start = 1
	}
	if a.End <= 0 || a.End-a.Start+1 > readFileLineCap {
		a.End = a.Start + readFileLineCap - 1
	}
	r.linesRead[a.Path] = append(r.linesRead[a.Path], lineRange{a.Start, a.End})
}

// reconKeyFor is the argument that identifies what an action was about.
func reconKeyFor(action string, args json.RawMessage) string {
	var a struct {
		Module   string `json:"module"`
		SymbolID string `json:"symbol_id"`
		Path     string `json:"path"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &a)
	}
	switch action {
	case "list_functions", "list_boundary_closures":
		return a.Module
	case "get_function_card", "get_callers":
		return a.SymbolID
	case "list_dir", "read_file", "tree_sitter_outline":
		return a.Path
	}
	return ""
}

// moduleOfSymbolID derives a symbol's module from its id. A SymbolID is
// lang:file:line:name(sig), and the module is a property of the file, so
// this reuses the same derivation the project map's cards were built with
// rather than a second rule that could disagree with them.
func moduleOfSymbolID(id string) string {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return projectmap.ModuleOf(parts[1])
}

// SawSymbol reports whether this pass actually looked at that definition.
//
// Two ways count. Opening its card with get_function_card is one. Reading
// the source across the line it is defined on is the other, and it is the
// stronger of the two — a card summarises, the source is the thing itself.
//
// It used to accept only the card. On runs/recon-003 the Planner resolved
// shdr_load_pub_key and check_update_version with find_symbols, read
// core/kernel/ree_fs_ta.c around the call, and raised a lead naming the
// real defect; the lead was refused because neither symbol had been opened
// as a card. The rule had confused how a function was observed with whether
// it was.
//
// find_symbols still does not count on its own. It resolves a name to
// candidate ids without showing any code, so a lead grounded on it alone
// would be a question about a name — which is exactly what this check is
// here to refuse.
func (r *ReconState) SawSymbol(id artifacts.SymbolID) bool {
	if r.Mode == ReconModeTreeOnly {
		path := strings.SplitN(string(id), "::", 2)[0]
		if validObservedPath(path) && len(r.linesRead[path]) > 0 {
			return true
		}
	}
	if r.symbolsViewed[string(id)] {
		return true
	}
	return r.readAcross(id)
}

// readAcross reports whether a read_file covered the line this symbol is
// defined on. A SymbolID is lang:file:line:name(sig).
func (r *ReconState) readAcross(id artifacts.SymbolID) bool {
	parts := strings.SplitN(string(id), ":", 4)
	if len(parts) < 4 {
		return false
	}
	line, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	for _, span := range r.linesRead[parts[1]] {
		if line >= span.start && line <= span.end {
			return true
		}
	}
	return false
}

// DistinctSymbolsViewed, DistinctModulesViewed and DistinctFilesRead are the
// gate's inputs, exposed for the ledger and for the refusal messages.
func (r *ReconState) DistinctSymbolsViewed() int { return len(r.symbolsViewed) }
func (r *ReconState) DistinctModulesViewed() int { return len(r.modulesViewed) }
func (r *ReconState) DistinctFilesRead() int     { return len(r.filesRead) }
func (r *ReconState) SymbolSpread() int          { return len(r.symbolSpread) }
func (r *ReconState) RelationQueries() int       { return r.relationQueries }
func (r *ReconState) LeadsOpened() int           { return r.leadsOpened }

// ModulesReviewed is the union of the modules listed and the modules the
// opened symbols came from, sorted.
func (r *ReconState) ModulesReviewed() []string {
	seen := map[string]bool{}
	for m := range r.modulesViewed {
		seen[m] = true
	}
	for m := range r.symbolSpread {
		seen[m] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// clamp lowers a floor to the repository's actual total, but only when that
// total is known. A zero total means the project map could not say, and
// clamping to it would satisfy the gate by knowing less.
func clamp(floor, total int) int {
	if total > 0 && total < floor {
		return total
	}
	return floor
}

// Satisfied reports whether this pass has done enough reconnaissance to be
// allowed to draw a conclusion.
func (r *ReconState) Satisfied() bool {
	return len(r.unmet()) == 0
}

// unmet lists what the gate is still waiting for, in the model's own
// vocabulary. A refusal that does not say what would lift it is a wall.
func (r *ReconState) unmet() []string {
	var missing []string
	switch r.Mode {
	case ReconModeIndexed:
		if !r.repositoryCardRead {
			missing = append(missing, "read the repository card (get_repository_card)")
		}
		if want := clamp(reconMinModules, r.modulesTotal); len(r.modulesViewed) < want {
			missing = append(missing, fmt.Sprintf(
				"list the functions of %d more module(s) (list_functions) — %d of %d so far",
				want-len(r.modulesViewed), len(r.modulesViewed), want))
		}
		if want := clamp(reconMinSymbols, r.functionsTotal); len(r.symbolsViewed) < want {
			missing = append(missing, fmt.Sprintf(
				"open %d more function card(s) (get_function_card) — %d of %d so far",
				want-len(r.symbolsViewed), len(r.symbolsViewed), want))
		}
		if want := clamp(reconMinSpread, r.modulesTotal); len(r.symbolSpread) < want {
			missing = append(missing, fmt.Sprintf(
				"open function cards from %d more module(s) — the ones you opened span %d of %d",
				want-len(r.symbolSpread), len(r.symbolSpread), want))
		}
		if r.relationQueries == 0 {
			missing = append(missing, "ask how something connects at least once (get_callers)")
		}
	case ReconModeTreeOnly:
		if !r.rootListed {
			missing = append(missing, "list the repository root (list_dir with path \".\")")
		}
		if want := clamp(minTreeReads, r.filesTotal); len(r.filesRead) < want {
			missing = append(missing, fmt.Sprintf(
				"read %d more source file(s) — %d of %d so far",
				want-len(r.filesRead), len(r.filesRead), want))
		}
	case ReconModeUnavailable:
		missing = append(missing,
			"this repository could not be indexed or listed, so there is nothing to browse; "+
				"reconnaissance will be released when its round budget runs out")
	}
	return missing
}

// Unmet is unmet(), rendered for a refusal message.
func (r *ReconState) Unmet() string {
	missing := r.unmet()
	if len(missing) == 0 {
		return ""
	}
	return "  - " + strings.Join(missing, "\n  - ")
}

// SkipReconnaissance starts the pass already investigating.
//
// Reconnaissance costs rounds, and a caller that budgeted none did not ask
// for it — an in-process test driving three scripted actions, or a caller
// wiring the planner for something else entirely. This is not the gate
// being switched off: it is the phase never being entered, and Status()
// says so rather than reporting an escape that was never used.
func (r *ReconState) SkipReconnaissance() {
	r.skipped = true
	r.phase = PhaseInvestigation
}

// Skipped reports whether this pass ever entered reconnaissance.
func (r *ReconState) Skipped() bool { return r.skipped }

// ExhaustReconBudget releases the gate because the reconnaissance rounds ran
// out. It is recorded rather than silent: a pass that concluded because it
// ran out of browsing time did not conclude for the same reason as one that
// finished looking.
func (r *ReconState) ExhaustReconBudget() { r.budgetExhausted = true }

func (r *ReconState) ExhaustReconTokenBudget() {
	r.budgetExhausted = true
	r.phase = PhaseInvestigation
}

// AllowDone reports whether `done` may be dispatched.
//
// The final round wins unconditionally. The forced-done prompt tells the
// model it MUST call done, and a gate that then refused it would leave the
// model with no legal action at all.
func (r *ReconState) AllowDone(isFinalRound bool) bool {
	if isFinalRound || r.budgetExhausted {
		return true
	}
	return !r.DoneCoverageIncomplete()
}

// AllowLead reports whether `open_audit_lead` may be dispatched.
//
// The gate blocks this too, not only `done`. Blocking only `done` lets the
// model open one function, raise a lead on it, flip to investigation and
// skip MAP entirely — which is the behaviour the gate exists to stop.
func (r *ReconState) AllowLead() bool {
	return r.skipped || r.budgetExhausted || r.Satisfied() || (r.Mode == ReconModeTreeOnly && len(r.linesRead) > 0)
}

// OpenedLead flips the pass into investigation. This is the only way Pass B
// opens.
func (r *ReconState) OpenedLead() {
	r.leadsOpened++
	r.phase = PhaseInvestigation
}

// Status is how the pass left reconnaissance.
func (r *ReconState) Status() string {
	switch {
	case r.skipped && !r.entryCoverageIncomplete():
		return reconStatusNotRequested
	case r.Satisfied() && !r.entryCoverageIncomplete():
		return reconStatusSatisfied
	case r.budgetExhausted:
		return reconStatusBudgetExhausted
	default:
		return reconStatusIncomplete
	}
}

// TerminationReason names the escape a run used, or "" when the gate was
// met on its own terms. finishedGated is true when the loop ended while
// reconnaissance was still incomplete.
func (r *ReconState) TerminationReason(finishedGated bool) string {
	// Entry reading is a completion requirement only for a no-lead result.
	// It deliberately does not feed Satisfied/AllowLead: useful evidence must
	// still be allowed to open investigation before every entry was sampled.
	if r.entryCoverageIncomplete() {
		if r.budgetExhausted {
			return terminationReconBudgetSpent
		}
		if finishedGated {
			return terminationReconIncomplete
		}
	}
	if r.skipped {
		return ""
	}
	if r.Satisfied() {
		return ""
	}
	if r.budgetExhausted {
		return terminationReconBudgetSpent
	}
	if finishedGated {
		return terminationReconIncomplete
	}
	return ""
}

// Source-based leads must name a normalized relative file that was actually
// read. Directory listings and failed reads never populate linesRead.
func validObservedPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}
