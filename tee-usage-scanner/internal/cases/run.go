package cases

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var repoMap artifacts.RepoMap
	if err := runfs.ReadJSON(runfs.RepoMapPath(cfg.RunDir), &repoMap); err != nil {
		return fmt.Errorf("load repo_map: %w", err)
	}

	var hotspots artifacts.HotspotIndex
	if err := runfs.ReadJSON(runfs.HotspotIndexPath(cfg.RunDir), &hotspots); err != nil {
		return fmt.Errorf("load hotspot_index: %w", err)
	}

	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return fmt.Errorf("ensure knowledge layout: %w", err)
	}

	packs, err := buildCasePacks(manifest, repoMap, hotspots.Hotspots, cfg.KnowledgeRoot, cfg.MaxCases)
	if err != nil {
		return err
	}
	for idx, pack := range packs {
		path := filepath.Join(runfs.CasePacksDir(cfg.RunDir), fmt.Sprintf("case-%03d.json", idx+1))
		if err := runfs.WriteJSON(path, pack); err != nil {
			return fmt.Errorf("write case pack %s: %w", pack.CaseID, err)
		}
	}
	fmt.Printf("Wrote %d case pack(s) to %s\n", len(packs), runfs.CasePacksDir(cfg.RunDir))
	return nil
}

// Enrich is the llm path's counterpart to Run. The Planner has already
// written the Case Packs — it knows which TWE investigation and which
// candidate produced each one, and that knowledge cannot be recovered from
// a hotspot index. Enrich therefore adds only the two things the Planner
// has no cheap way to produce: source snippets for the target files, and
// knowledge-base hints looked up from the pack itself.
//
// Run stays exactly as it was and continues to serve the legacy path.
func Enrich(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return fmt.Errorf("ensure knowledge layout: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", p, err)
		}
		pack.Snippets = mergeSnippets(pack.Snippets, collectSnippets(manifest.LocalPath, pack.TargetFiles, pack.TargetSymbols))
		hints, err := knowledge.LookupForCase(cfg.KnowledgeRoot, pack, 4)
		if err != nil {
			return fmt.Errorf("lookup knowledge for %s: %w", pack.CaseID, err)
		}
		pack.KnowledgeHints = hints
		if err := runfs.WriteJSON(p, pack); err != nil {
			return fmt.Errorf("write case pack %s: %w", p, err)
		}
	}
	fmt.Printf("Enriched %d case pack(s) in %s\n", len(paths), runfs.CasePacksDir(cfg.RunDir))
	return nil
}

func buildCasePacks(manifest artifacts.Manifest, repoMap artifacts.RepoMap, hotspots []artifacts.Hotspot, knowledgeRoot string, maxCases int) ([]artifacts.CasePack, error) {
	limit := maxCases
	if limit <= 0 || limit > len(hotspots) {
		limit = len(hotspots)
	}
	repoName := sanitizeSlug(filepath.Base(manifest.LocalPath))
	if repoName == "" {
		repoName = "repo"
	}
	commit := manifest.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	var packs []artifacts.CasePack
	for idx, hotspot := range hotspots[:limit] {
		category, obligations, openQuestions := caseTemplate(hotspot.Kind)
		pack := artifacts.CasePack{
			SchemaVersion:       "teecheck.case_pack.v1",
			CaseID:              fmt.Sprintf("%s@%s:%s:%s:%03d", repoName, commit, sanitizeSlug(manifest.Focus), category, idx+1),
			HotspotID:           hotspot.HotspotID,
			Focus:               manifest.Focus,
			Category:            category,
			Priority:            hotspot.Priority,
			TargetFiles:         append([]string{}, hotspot.Paths...),
			TargetSymbols:       append([]string{}, hotspot.Symbols...),
			WhySelected:         append([]string{}, hotspot.WhySelected...),
			ToolFacts:           collectToolFacts(repoMap, hotspot),
			GraphFacts:          collectGraphFacts(hotspot),
			Snippets:            collectSnippets(manifest.LocalPath, hotspot.Paths, hotspot.Symbols),
			ExpectedObligations: obligations,
			OpenQuestions:       openQuestions,
		}
		hints, err := knowledge.LookupForCase(knowledgeRoot, pack, 4)
		if err != nil {
			return nil, fmt.Errorf("lookup knowledge for %s: %w", pack.CaseID, err)
		}
		pack.KnowledgeHints = hints
		packs = append(packs, pack)
	}
	return packs, nil
}

func collectToolFacts(repoMap artifacts.RepoMap, hotspot artifacts.Hotspot) []string {
	var facts []string
	for _, boundary := range repoMap.Boundaries {
		for _, path := range hotspot.Paths {
			if contains(boundary.Paths, path) {
				facts = append(facts, fmt.Sprintf("boundary %s (%s)", boundary.Kind, boundary.Direction))
			}
		}
	}
	return uniqStrings(facts)
}

func collectGraphFacts(hotspot artifacts.Hotspot) []string {
	facts := []string{
		fmt.Sprintf("hotspot kind: %s", hotspot.Kind),
		fmt.Sprintf("priority: %s", hotspot.Priority),
	}
	if len(hotspot.Symbols) > 0 {
		facts = append(facts, "symbols: "+strings.Join(hotspot.Symbols, ", "))
	}
	return facts
}

// mergeSnippets combines pre-existing pack snippets with freshly collected
// ones, deduped by (path, start line). Pre-existing snippets come first: on
// the deterministic fact lane they are the DEFINITIONS the finding turns on
// (producer/authority bodies, produced structs — internal/pipeline
// evidence_window.go), and Enrich's generic collector would otherwise
// overwrite them with first-mention windows of the same files, recreating
// exactly the evidence-window gap the enrichment exists to close. Planner
// packs arrive here with no snippets, so for them mergeSnippets is an
// identity over the collected list.
func mergeSnippets(existing, collected []artifacts.PromptSnippet) []artifacts.PromptSnippet {
	if len(existing) == 0 {
		return collected
	}
	seen := make(map[string]bool, len(existing)+len(collected))
	out := make([]artifacts.PromptSnippet, 0, len(existing)+len(collected))
	for _, s := range existing {
		key := s.Path + ":" + strconv.Itoa(s.StartLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	for _, s := range collected {
		key := s.Path + ":" + strconv.Itoa(s.StartLine)
		if seen[key] {
			continue
		}
		// A collected snippet redundant with an existing (definition)
		// snippet of the same file adds nothing — in EITHER containment
		// direction: a first-mention window inside the definition slice,
		// or the generic whole-file snippet of a small file that contains
		// it (the OP-TEE producer case: a 411-line whole-file snippet over
		// a 30-line definition). Existing-first ordering already prefers
		// the curated definition.
		redundant := false
		for _, e := range existing {
			if e.Path != s.Path {
				continue
			}
			if (s.StartLine >= e.StartLine && s.EndLine <= e.EndLine) ||
				(e.StartLine >= s.StartLine && e.EndLine <= s.EndLine) {
				redundant = true
				break
			}
		}
		if redundant {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// snippetSmallFileLineCap controls when collectSnippets returns the
// entire file as a single snippet vs symbol-anchored windows. Files
// at or below this length are included whole.
const snippetSmallFileLineCap = 500

// snippetWindowRadius is the number of lines extracted on each side
// of a symbol match in a large file. The window covers
// 2*radius+1 lines centered on the match.
const snippetWindowRadius = 50

// snippetFallbackHeadLines is the number of leading lines included
// when no symbols are provided or none of them match in a large file.
// Larger than the historical 18 so reviewers see useful context.
const snippetFallbackHeadLines = 80

// collectSnippets reads each (deduped) path in paths and returns
// PromptSnippets sized to give downstream LLM agents enough context
// to reason about the candidate.
//
// Strategy:
//  1. Small file (<= snippetSmallFileLineCap lines): include the entire file.
//  2. Large file with at least one symbol matching its content: extract
//     a window of ±snippetWindowRadius lines around each first match, then
//     merge overlapping windows into a single snippet.
//  3. Large file with no symbol matches: fall back to the first
//     snippetFallbackHeadLines lines (was 18 in v1 — too small).
//
// This replaces the v1 behavior of always returning the first 18 lines,
// which left expert/challenger blind to anything past the import block.
func collectSnippets(repoRoot string, paths []string, symbols []string) []artifacts.PromptSnippet {
	var snippets []artifacts.PromptSnippet
	for _, rel := range uniqStrings(paths) {
		full := filepath.Join(repoRoot, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		// Drop trailing empty line from a final newline.
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		total := len(lines)
		if total == 0 {
			continue
		}

		relSlash := filepath.ToSlash(rel)

		// Case 1: small file, include everything.
		if total <= snippetSmallFileLineCap {
			snippets = append(snippets, artifacts.PromptSnippet{
				Path:      relSlash,
				StartLine: 1,
				EndLine:   total,
				Content:   strings.Join(lines, "\n"),
			})
			continue
		}

		// Case 2: large file. Find the first line each symbol appears on.
		var hits []int
		for _, sym := range symbols {
			sym = strings.TrimSpace(sym)
			if sym == "" {
				continue
			}
			for i, line := range lines {
				if strings.Contains(line, sym) {
					hits = append(hits, i+1) // 1-indexed
					break
				}
			}
		}

		// Case 3: no hits, fall back to head.
		if len(hits) == 0 {
			end := snippetFallbackHeadLines
			if end > total {
				end = total
			}
			snippets = append(snippets, artifacts.PromptSnippet{
				Path:      relSlash,
				StartLine: 1,
				EndLine:   end,
				Content:   strings.Join(lines[:end], "\n"),
			})
			continue
		}

		// Build merged windows from hits.
		windows := mergeLineWindows(hits, snippetWindowRadius, total)
		for _, w := range windows {
			snippets = append(snippets, artifacts.PromptSnippet{
				Path:      relSlash,
				StartLine: w.start,
				EndLine:   w.end,
				Content:   strings.Join(lines[w.start-1:w.end], "\n"),
			})
		}
	}
	return snippets
}

// lineWindow is a 1-indexed inclusive line range.
type lineWindow struct {
	start, end int
}

// mergeLineWindows takes a list of 1-indexed center lines and a
// per-side radius, expands each to a [center-radius, center+radius]
// window clamped to [1, total], then merges any overlapping or
// touching windows. Returns the merged windows in start-line order.
func mergeLineWindows(hits []int, radius, total int) []lineWindow {
	if len(hits) == 0 {
		return nil
	}
	wins := make([]lineWindow, 0, len(hits))
	for _, h := range hits {
		s := h - radius
		if s < 1 {
			s = 1
		}
		e := h + radius
		if e > total {
			e = total
		}
		wins = append(wins, lineWindow{s, e})
	}
	// Sort by start.
	sort.Slice(wins, func(i, j int) bool { return wins[i].start < wins[j].start })
	merged := []lineWindow{wins[0]}
	for _, w := range wins[1:] {
		last := &merged[len(merged)-1]
		if w.start <= last.end+1 {
			if w.end > last.end {
				last.end = w.end
			}
		} else {
			merged = append(merged, w)
		}
	}
	return merged
}

func caseTemplate(kind string) (string, []string, []string) {
	switch kind {
	case "attestation":
		return "attestation",
			[]string{"attestation and identity verification", "freshness and replay resistance", "secure failure behavior"},
			[]string{"Is there helper logic outside the current file that completes verification?"}
	case "authorization":
		return "authorization",
			[]string{"authorization and caller binding", "trust-boundary revalidation", "secure failure behavior"},
			[]string{"Does an upstream wrapper perform the binding instead of this unit?"}
	case "state_machine":
		return "state_machine",
			[]string{"state-machine enforcement", "freshness and replay resistance", "secure failure behavior"},
			[]string{"Which state preconditions are enforced elsewhere?"}
	case "key_management":
		return "key_management",
			[]string{"key and secret handling", "authorization and caller binding", "secure failure behavior"},
			[]string{"Are key lifecycle checks abstracted behind helper APIs?"}
	case "fallback":
		return "fallback",
			[]string{"secure failure behavior", "trust-boundary revalidation"},
			[]string{"Is the apparent fallback actually a safe diagnostic path?"}
	default:
		return "boundary",
			[]string{"trust-boundary revalidation", "authorization and caller binding", "secure failure behavior"},
			[]string{"Is there surrounding context that changes the actual trust boundary?"}
	}
}

func sanitizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "@", "-", ".", "-", "_", "-", " ", "-")
	value = replacer.Replace(value)
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return strings.Trim(value, "-")
}

func uniqStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
