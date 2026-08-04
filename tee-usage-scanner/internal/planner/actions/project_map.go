package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Negative-evidence vocabulary (docs/ARCHITECTURE.md §7). A refusal that
// does not name its scope is how "no caller found" becomes "no caller
// exists" — the inference that turned a live delegation path into "dead
// code" on CVE-2026-44362.
const (
	scopeIndexedRepository = "not_found_in_indexed_repository"
	scopeUnavailableIndex  = "not_found_in_partial_scope"
)

// browseIndex is one run's index and map, loaded once.
//
// The capsule set is megabytes; re-reading it per action would make a
// paged browse quadratic in the number of pages. Pages themselves are read
// from their own files, which is what pre-writing them is for.
type browseIndex struct {
	facts  artifacts.RepoFacts
	m      artifacts.ProjectMap
	byID   map[artifacts.SymbolID]artifacts.FunctionCapsule
	byName map[string][]artifacts.FunctionCapsule
}

func loadBrowseIndex(runDir string) (*browseIndex, error) {
	var b browseIndex
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &b.facts); err != nil {
		return nil, fmt.Errorf("program index unavailable: %w", err)
	}
	if err := runfs.ReadJSON(runfs.ProjectMapPath(runDir), &b.m); err != nil {
		return nil, fmt.Errorf("project map unavailable: %w", err)
	}
	b.byID = make(map[artifacts.SymbolID]artifacts.FunctionCapsule, len(b.facts.Capsules))
	b.byName = map[string][]artifacts.FunctionCapsule{}
	for _, c := range b.facts.Capsules {
		b.byID[c.SymbolID] = c
		b.byName[c.Name] = append(b.byName[c.Name], c)
	}
	return &b, nil
}

// indexUnavailable reports the note a handler must return instead of an
// empty result when there is no index. An empty answer and an absent index
// are the same shape to a reading model, and only one of them is a fact
// about the code.
func (b *browseIndex) indexUnavailable() string {
	if b.facts.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		return ""
	}
	note := b.facts.IndexNote
	if note == "" {
		note = "no reason recorded"
	}
	return fmt.Sprintf("The program index is unavailable for this run (%s: %s). "+
		"Nothing was searched, which is not evidence about the code — use list_dir, "+
		"ripgrep and read_file, whose answers stand on their own.", scopeUnavailableIndex, note)
}

// observe caps a handler's output at the one shared limit and says so when
// it cuts. A silent cut is the failure mode: the model reads a prefix and
// has no way to know the rest exists.
func observe(name, body string) ActionResult {
	if len(body) <= observationlimits.MaxBytes {
		return ActionResult{Name: name, OK: true, Output: body}
	}
	const notice = "\n\n[truncated at the observation limit — ask for a narrower page or a specific symbol_id; " +
		"the absence of a result below this point is not evidence that it does not exist]"
	cut := observationlimits.MaxBytes - len(notice)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && cut < len(body) && (body[cut]&0xC0) == 0x80 {
		cut--
	}
	return ActionResult{Name: name, OK: true, Output: body[:cut] + notice, Truncated: true}
}

// openIndex is the shared prologue: load, and refuse with the index's own
// note when there is nothing to browse.
func openIndex(name, runDir string) (*browseIndex, *ActionResult) {
	b, err := loadBrowseIndex(runDir)
	if err != nil {
		r := fail(name, err.Error())
		return nil, &r
	}
	if note := b.indexUnavailable(); note != "" {
		r := fail(name, note)
		return nil, &r
	}
	return b, nil
}

// ─── get_repository_card ────────────────────────────────────────────────

type GetRepositoryCardHandler struct{}

func (GetRepositoryCardHandler) Name() string { return "get_repository_card" }

func (h GetRepositoryCardHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	b, err := loadBrowseIndex(req.RunDir)
	if err != nil {
		return fail(h.Name(), err.Error())
	}
	card := b.m.Repository
	var out strings.Builder
	fmt.Fprintf(&out, "repository: %d file(s)\n", card.FileCount)
	if len(card.Languages) > 0 {
		fmt.Fprintf(&out, "languages: %s\n", strings.Join(card.Languages, ", "))
	}
	if len(card.BuildTargets) > 0 {
		fmt.Fprintf(&out, "build: %s\n", strings.Join(card.BuildTargets, ", "))
	}
	fmt.Fprintf(&out, "modules: %d\n", len(b.m.Modules))
	// The capabilities travel with every answer: what the index can and
	// cannot say is part of reading any of it.
	fmt.Fprintf(&out, "index capabilities: symbols=%s direct_calls=%s field_accesses=%s build_reachability=%s\n",
		b.m.Capabilities.Symbols, b.m.Capabilities.DirectCalls,
		b.m.Capabilities.FieldAccesses, b.m.Capabilities.BuildReachability)
	if b.facts.IndexNote != "" {
		fmt.Fprintf(&out, "index note: %s\n", b.facts.IndexNote)
	}
	if card.DocumentedPurpose != "" {
		// Quoted from the repository's own README, not summarised.
		fmt.Fprintf(&out, "\ndocumented purpose (quoted from the README):\n%s\n", card.DocumentedPurpose)
	} else {
		out.WriteString("\ndocumented purpose: none — the repository has no README this run could read\n")
	}
	return observe(h.Name(), out.String())
}

// ─── list_modules ───────────────────────────────────────────────────────

type ListModulesHandler struct{}

func (ListModulesHandler) Name() string { return "list_modules" }

func (h ListModulesHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%d module(s). files and functions are what tell a project's own code "+
		"from vendored dependencies.\n\n", len(b.m.Modules))
	for _, c := range b.m.Modules {
		fmt.Fprintf(&out, "%s  %d file(s), %d function(s)", c.Path, c.FileCount, c.FunctionCount)
		if len(c.CallsModules) > 0 {
			fmt.Fprintf(&out, "  calls: %s", strings.Join(c.CallsModules, ", "))
		}
		if len(c.CalledByModules) > 0 {
			fmt.Fprintf(&out, "  called by: %s", strings.Join(c.CalledByModules, ", "))
		}
		out.WriteByte('\n')
	}
	return observe(h.Name(), out.String())
}

// ─── list_functions ─────────────────────────────────────────────────────

type listFunctionsArgs struct {
	Module string `json:"module"`
	Page   int    `json:"page"`
}

type ListFunctionsHandler struct{}

func (ListFunctionsHandler) Name() string { return "list_functions" }

func (h ListFunctionsHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args listFunctionsArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
	}
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}

	var refs []artifacts.FunctionCardPageRef
	for _, r := range b.m.FunctionPages {
		if r.Module == args.Module {
			refs = append(refs, r)
		}
	}
	if len(refs) == 0 {
		return fail(h.Name(), fmt.Sprintf(
			"%s: no function card page for module %q. The index covers %d module(s); "+
				"call list_modules for their names. A module absent here has no indexed "+
				"functions, which is not the same as having none.",
			scopeIndexedRepository, args.Module, len(b.m.Modules)))
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Page < refs[j].Page })
	if args.Page < 0 || args.Page >= len(refs) {
		return fail(h.Name(), fmt.Sprintf(
			"%s: module %q has pages 0..%d, not %d",
			scopeIndexedRepository, args.Module, len(refs)-1, args.Page))
	}

	ref := refs[args.Page]
	var page []artifacts.FunctionCapsule
	if err := runfs.ReadJSON(filepath.Join(req.RunDir, filepath.FromSlash(ref.Path)), &page); err != nil {
		return fail(h.Name(), fmt.Sprintf("page %s: %v", ref.Path, err))
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%s — page %d of %d, %d function(s) on this page\n\n",
		args.Module, args.Page, len(refs), len(page))
	for _, c := range page {
		writeCapsuleLine(&out, c)
	}
	if args.Page+1 < len(refs) {
		// Named explicitly so the model does not have to infer the next
		// request from the page number.
		fmt.Fprintf(&out, "\nnext_cursor: {\"module\": %q, \"page\": %d}\n", args.Module, args.Page+1)
	} else {
		out.WriteString("\nlast page of this module\n")
	}
	return observe(h.Name(), out.String())
}

func writeCapsuleLine(out *strings.Builder, c artifacts.FunctionCapsule) {
	fmt.Fprintf(out, "%s  %s:%d  id=%s\n", c.Name, c.File, c.Line, c.SymbolID)
	if len(c.Calls) > 0 {
		fmt.Fprintf(out, "    calls %d\n", len(c.Calls))
	}
	if len(c.CalledBy) > 0 {
		fmt.Fprintf(out, "    called by %d\n", len(c.CalledBy))
	}
	if len(c.FieldAccesses) > 0 {
		fmt.Fprintf(out, "    touches: %s\n", strings.Join(c.FieldAccesses, ", "))
	}
	if len(c.DirectFieldWrites) > 0 {
		fmt.Fprintf(out, "    writes:  %s\n", strings.Join(c.DirectFieldWrites, ", "))
	}
}

// ─── find_symbols ───────────────────────────────────────────────────────

type findSymbolsArgs struct {
	Name string `json:"name"`
	Page int    `json:"page"`
}

// findSymbolsPageSize bounds one page of candidates. "Return every
// candidate" and "never exceed the observation cap" cannot both hold on a
// name with hundreds of matches, so the count is stated and the rest paged.
const findSymbolsPageSize = 50

type FindSymbolsHandler struct{}

func (FindSymbolsHandler) Name() string { return "find_symbols" }

func (h FindSymbolsHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args findSymbolsArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
	}
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}

	matches := append([]artifacts.FunctionCapsule(nil), b.byName[strings.TrimSpace(args.Name)]...)
	if len(matches) == 0 {
		return fail(h.Name(), fmt.Sprintf(
			"%s: no indexed definition named %q. The index holds definitions the "+
				"extractor could see; a name absent here may still exist in a macro, in "+
				"assembly, or in a translation unit that was skipped. Use ripgrep to check.",
			scopeIndexedRepository, args.Name))
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].File != matches[j].File {
			return matches[i].File < matches[j].File
		}
		return matches[i].Line < matches[j].Line
	})

	pages := (len(matches) + findSymbolsPageSize - 1) / findSymbolsPageSize
	if args.Page < 0 || args.Page >= pages {
		args.Page = 0
	}
	start := args.Page * findSymbolsPageSize
	end := start + findSymbolsPageSize
	if end > len(matches) {
		end = len(matches)
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%d match(es) for %q — page %d of %d.\n", len(matches), args.Name, args.Page, pages)
	if len(matches) > 1 {
		// Deliberately not resolved here: two files can each define a static
		// function of the same name, and picking one is the identity guess
		// SymbolID exists to prevent.
		out.WriteString("More than one definition carries this name; choose by symbol_id.\n")
	}
	out.WriteByte('\n')
	for _, c := range matches[start:end] {
		fmt.Fprintf(&out, "%s:%d  module=%s  id=%s\n", c.File, c.Line, c.Module, c.SymbolID)
	}
	if args.Page+1 < pages {
		fmt.Fprintf(&out, "\nnext_cursor: {\"name\": %q, \"page\": %d}\n", args.Name, args.Page+1)
	}
	return observe(h.Name(), out.String())
}

// ─── get_function_card ──────────────────────────────────────────────────

type symbolIDArgs struct {
	SymbolID string `json:"symbol_id"`
}

type GetFunctionCardHandler struct{}

func (GetFunctionCardHandler) Name() string { return "get_function_card" }

func (h GetFunctionCardHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args symbolIDArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
	}
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}
	c, ok := b.byID[artifacts.SymbolID(strings.TrimSpace(args.SymbolID))]
	if !ok {
		return fail(h.Name(), unknownSymbolNote(b, args.SymbolID))
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%s  %s:%d\nmodule: %s\nid: %s\n\n", c.Name, c.File, c.Line, c.Module, c.SymbolID)
	fmt.Fprintf(&out, "calls (%s): %s\n", c.CallersScope(), joinIDs(c.Calls))
	fmt.Fprintf(&out, "called by (%s): %s\n", c.CallersScope(), joinIDs(c.CalledBy))
	fmt.Fprintf(&out, "\nfields touched (read or written): %s\n", joinOrNone(c.FieldAccesses))
	fmt.Fprintf(&out, "fields written (%s): %s\n", c.FieldWritesScope(), joinOrNone(c.DirectFieldWrites))
	out.WriteString("\nA field absent from the written list was not proved to be assigned " +
		"here; memcpy, a pointer alias and a designated initializer are all outside " +
		"what that check can see.\n")
	return observe(h.Name(), out.String())
}

// maxNearMatchesNamed bounds the near-match list. A refusal is an
// observation like any other and must stay inside the shared budget.
const maxNearMatchesNamed = 10

// unknownSymbolNote refuses a symbol_id the index does not hold.
//
// It first checks whether the id is a prefix of ids that do exist, because
// that is what a dropped signature looks like: a SymbolID is
// lang:file:line:name(signature), and on the first real run against OP-TEE
// the model opened a card with the full id and then asked get_callers about
// the same function with everything after the name removed. Both refusals
// were correct and neither said what was wrong, so the run finished with
// zero relation queries — the one reconnaissance requirement it never met.
//
// Naming the candidates is not choosing between them. When several
// definitions share a prefix they are listed and the caller picks, exactly
// as find_symbols does.
func unknownSymbolNote(b *browseIndex, id string) string {
	trimmed := strings.TrimSpace(id)
	if near := b.idsBeginningWith(trimmed); len(near) > 0 {
		shown := near
		more := ""
		if len(shown) > maxNearMatchesNamed {
			shown = shown[:maxNearMatchesNamed]
			more = fmt.Sprintf("\n  ... and %d more", len(near)-maxNearMatchesNamed)
		}
		return fmt.Sprintf(
			"%s: %q is not a complete symbol_id. A symbol_id is "+
				"lang:file:line:name(signature), and the signature is part of it — two "+
				"definitions can agree on everything before it. %d id(s) in the index "+
				"begin with what you sent:\n  %s%s\nAsk again with one of these, copied exactly.",
			scopeIndexedRepository, trimmed, len(near), strings.Join(shown, "\n  "), more)
	}
	return fmt.Sprintf(
		"%s: %q is not in the program index. The index holds definitions the extractor "+
			"could see; a symbol absent here may still exist in a macro, in assembly, or "+
			"in a translation unit that was skipped. This is not evidence that it does "+
			"not exist — use find_symbols by name, or ripgrep.",
		scopeIndexedRepository, id)
}

// idsBeginningWith returns the indexed ids that start with prefix, sorted.
// An exact id is never its own near match: this is only reached when the
// lookup already missed.
func (b *browseIndex) idsBeginningWith(prefix string) []string {
	if prefix == "" {
		return nil
	}
	var out []string
	for id := range b.byID {
		if strings.HasPrefix(string(id), prefix) {
			out = append(out, string(id))
		}
	}
	sort.Strings(out)
	return out
}

func joinIDs(ids []artifacts.SymbolID) string {
	if len(ids) == 0 {
		return "(none in the index)"
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return strings.Join(out, ", ")
}

func joinOrNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}

// ─── get_callers ────────────────────────────────────────────────────────

type GetCallersHandler struct{}

func (GetCallersHandler) Name() string { return "get_callers" }

func (h GetCallersHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args symbolIDArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
	}
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}
	c, ok := b.byID[artifacts.SymbolID(strings.TrimSpace(args.SymbolID))]
	if !ok {
		return fail(h.Name(), unknownSymbolNote(b, args.SymbolID))
	}

	var out strings.Builder
	fmt.Fprintf(&out, "callers of %s (%s:%d): %d\n\n", c.Name, c.File, c.Line, len(c.CalledBy))
	for _, id := range c.CalledBy {
		if caller, known := b.byID[id]; known {
			fmt.Fprintf(&out, "%s  %s:%d  id=%s\n", caller.Name, caller.File, caller.Line, id)
		} else {
			fmt.Fprintf(&out, "%s\n", id)
		}
	}

	// The limits ship with the answer. An empty caller list read without
	// them becomes "unreachable", which is the inference that turned a live
	// delegation path into dead code on CVE-2026-44362 — the fact layer had
	// already located the caller.
	f := b.facts
	fmt.Fprintf(&out, "\nscope: %s (capability: %s)\n", c.CallersScope(), f.Capabilities.DirectCalls)
	fmt.Fprintf(&out, "this list omits, repository-wide:\n")
	fmt.Fprintf(&out, "  %d call site(s) with no nameable target at all\n", f.UnresolvedCallSiteCount)
	fmt.Fprintf(&out, "  %d call site(s) whose callee has no definition in this tree\n", f.ExternalCallSites)
	fmt.Fprintf(&out, "  %d call site(s) whose callee is defined several times, where which "+
		"definition links is not decidable from the source\n", f.AmbiguousCallSites)
	fmt.Fprintf(&out, "of %d call site(s) total. An absent caller is not proof of unreachability.\n",
		f.TotalCallSites)
	return observe(h.Name(), out.String())
}

var (
	_ Handler = GetRepositoryCardHandler{}
	_ Handler = ListModulesHandler{}
	_ Handler = ListFunctionsHandler{}
	_ Handler = FindSymbolsHandler{}
	_ Handler = GetFunctionCardHandler{}
	_ Handler = GetCallersHandler{}
)
