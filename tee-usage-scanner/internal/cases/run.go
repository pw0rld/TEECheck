package cases

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	var profile artifacts.ProjectProfile
	if err := runfs.ReadJSON(runfs.ProjectProfilePath(cfg.RunDir), &profile); err != nil {
		return fmt.Errorf("load project profile: %w", err)
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

	packs, err := buildCasePacks(manifest, profile, repoMap, hotspots.Hotspots, cfg.KnowledgeRoot, cfg.MaxCases)
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

func buildCasePacks(manifest artifacts.Manifest, profile artifacts.ProjectProfile, repoMap artifacts.RepoMap, hotspots []artifacts.Hotspot, knowledgeRoot string, maxCases int) ([]artifacts.CasePack, error) {
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
			ToolFacts:           collectToolFacts(profile, repoMap, hotspot),
			GraphFacts:          collectGraphFacts(hotspot),
			Snippets:            collectSnippets(manifest.LocalPath, hotspot.Paths),
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

func collectToolFacts(profile artifacts.ProjectProfile, repoMap artifacts.RepoMap, hotspot artifacts.Hotspot) []string {
	var facts []string
	if len(profile.FrameworkHints) > 0 {
		facts = append(facts, "framework hints: "+strings.Join(profile.FrameworkHints, ", "))
	}
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

func collectSnippets(repoRoot string, paths []string) []artifacts.PromptSnippet {
	var snippets []artifacts.PromptSnippet
	for _, rel := range uniqStrings(paths) {
		full := filepath.Join(repoRoot, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		end := len(lines)
		if end > 18 {
			end = 18
		}
		snippets = append(snippets, artifacts.PromptSnippet{
			Path:      filepath.ToSlash(rel),
			StartLine: 1,
			EndLine:   end,
			Content:   strings.Join(lines[:end], "\n"),
		})
	}
	return snippets
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
