// Package projectmap derives the neutral navigation view the Planner
// browses from the program index.
//
// It carries structure and size, never a judgement about where to look:
// selecting audit targets is a Planner runtime behaviour, and the amplification chain
// traces what happens when the 01 stage decides it instead. The map never
// embeds the capsules themselves — the measured set is 6.36 MB over 11,301
// definitions, which no prompt can carry — so the pages are written to disk
// and fetched one at a time.
package projectmap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// skipDirs are excluded from the per-module file counts: they hold no
// auditable source, and .git alone would swamp every real module.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
}

// buildFileNames are what a repository's build system looks like at the
// root. Detected by name rather than parsed: the map says which build system
// is present, and anything more is a claim the Planner should verify.
var buildFileNames = map[string]string{
	"Makefile":       "make",
	"makefile":       "make",
	"CMakeLists.txt": "cmake",
	"meson.build":    "meson",
	"go.mod":         "go",
	"Cargo.toml":     "cargo",
	"package.json":   "npm",
	"setup.py":       "setuptools",
	"pyproject.toml": "python",
}

var readmeNames = []string{"README.md", "README", "README.rst", "README.txt", "Readme.md", "readme.md"}

// Run derives the project map from repo_facts.v1.json and writes it, along
// with one function-card page file per page.
//
// A degraded index is not a failure. The map still describes what the tree
// looks like — modules, sizes, the README — and carries the index's own
// capability verdicts forward, so a Planner browsing it can tell an empty
// module list from an index that was never built.
func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(cfg.RunDir), &facts); err != nil {
		return fmt.Errorf("load repo facts: %w", err)
	}

	fileCounts, totalFiles := countFiles(manifest.LocalPath)

	m := artifacts.ProjectMap{
		SchemaVersion: artifacts.SchemaVersionProjectMapV1,
		RunID:         manifest.RunID,
		Scope:         manifest.Scope,
		// Carried forward verbatim. A Planner reading the map must be able to
		// tell "this module has no recorded functions" from "no index was
		// built", and the map is the only thing it reads.
		Capabilities:   facts.Capabilities,
		CoverageStatus: facts.CoverageStatus,
		Repository: artifacts.RepositoryCard{
			DocumentedPurpose: documentedPurpose(readFirstReadme(manifest.LocalPath)),
			Languages:         facts.Languages,
			BuildTargets:      detectBuildTargets(manifest.LocalPath),
			FileCount:         totalFiles,
		},
		Modules: buildModuleCards(facts, fileCounts),
	}

	pages, err := writePages(cfg.RunDir, facts.Capsules)
	if err != nil {
		return err
	}
	m.FunctionPages = pages
	if len(pages) == 0 {
		m.Capabilities.Symbols = artifacts.CapabilityUnavailable
		m.CoverageStatus = artifacts.CapabilityPartial
	}

	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal project map: %w", err)
	}
	if err := schema.Validate(schema.ProjectMapV1, data); err != nil {
		return fmt.Errorf("project map failed schema validation: %w", err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(cfg.RunDir), m); err != nil {
		return fmt.Errorf("write project map: %w", err)
	}
	fmt.Printf("Project map: %d module(s), %d function card page(s)\n", len(m.Modules), len(m.FunctionPages))
	return nil
}

// writePages groups the capsules by module, paginates each module by bytes,
// and writes every page to its own file.
//
// Pre-writing is what keeps the browse action from deserialising the whole
// index on every call: repo_facts.v1.json is megabytes, and a Planner paging
// through modules would read all of it once per page.
func writePages(runDir string, capsules []artifacts.FunctionCapsule) ([]artifacts.FunctionCardPageRef, error) {
	byModule := map[string][]artifacts.FunctionCapsule{}
	for _, c := range capsules {
		byModule[c.Module] = append(byModule[c.Module], c)
	}
	modules := make([]string, 0, len(byModule))
	for m := range byModule {
		modules = append(modules, m)
	}
	sort.Strings(modules)

	var refs []artifacts.FunctionCardPageRef
	for _, module := range modules {
		in := byModule[module]
		sort.Slice(in, func(i, j int) bool { return in[i].SymbolID < in[j].SymbolID })
		for i, page := range paginate(in) {
			ref := pageRef(module, i, len(page))
			full := filepath.Join(runDir, filepath.FromSlash(ref.Path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return nil, fmt.Errorf("create function card dir: %w", err)
			}
			if err := runfs.WriteJSON(full, page); err != nil {
				return nil, fmt.Errorf("write function card page: %w", err)
			}
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// countFiles walks the tree once, returning the per-module counts and the
// total. A root that cannot be walked yields zero counts rather than an
// error: the map is still worth writing, and the stage that needs the files
// should fail with its own message.
func countFiles(root string) (map[string]int, int) {
	counts := map[string]int{}
	total := 0
	if root == "" {
		return counts, 0
	}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		counts[ModuleOf(filepath.ToSlash(rel))]++
		total++
		return nil
	})
	return counts, total
}

func detectBuildTargets(root string) []string {
	if root == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for name, target := range buildFileNames {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil && !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	sort.Strings(out)
	return out
}

// readFirstReadme returns the contents of the first README it finds, or "".
// A repository with no README yields an empty documented purpose, which is
// the honest answer — an invented one would be an inference wearing a
// quote's clothes.
func readFirstReadme(root string) string {
	if root == "" {
		return ""
	}
	for _, name := range readmeNames {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err == nil {
			return string(body)
		}
	}
	return ""
}
