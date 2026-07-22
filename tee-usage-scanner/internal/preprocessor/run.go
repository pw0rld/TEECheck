package preprocessor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

var extLanguages = map[string]string{
	".rs":  "rust",
	".go":  "go",
	".c":   "c",
	".cc":  "cpp",
	".cpp": "cpp",
	".h":   "c-header",
	".hpp": "cpp-header",
	".sol": "solidity",
	".ts":  "typescript",
	".tsx": "typescript",
	".js":  "javascript",
	".py":  "python",
}

func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	profile, err := buildProfile(manifest)
	if err != nil {
		return err
	}
	if err := runfs.WriteJSON(runfs.ProjectProfilePath(cfg.RunDir), profile); err != nil {
		return fmt.Errorf("write project profile: %w", err)
	}
	profileV2, err := buildProfileV2(manifest, profile)
	if err != nil {
		return fmt.Errorf("build project profile v2: %w", err)
	}
	if err := runfs.WriteJSON(runfs.ContextProjectProfilePath(cfg.RunDir), profileV2); err != nil {
		return fmt.Errorf("write project profile v2: %w", err)
	}
	tweContextWritten, err := compileTWEKnowledge(cfg.KnowledgeRoot, cfg.RunDir)
	if err != nil {
		return fmt.Errorf("compile TWE prior knowledge: %w", err)
	}
	fmt.Printf("Project profile written to %s\n", runfs.ProjectProfilePath(cfg.RunDir))
	fmt.Printf("Project profile v2 written to %s\n", runfs.ContextProjectProfilePath(cfg.RunDir))
	if tweContextWritten {
		fmt.Printf("TWE agent context written to %s\n", runfs.TWEAgentContextPath(cfg.RunDir))
	}
	return nil
}

func buildProfile(manifest artifacts.Manifest) (artifacts.ProjectProfile, error) {
	languageCounts := map[string]int{}
	topLevelSet := map[string]bool{}
	sensitiveSet := map[string]bool{}
	frameworkSet := map[string]bool{}

	err := filepath.Walk(manifest.LocalPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(manifest.LocalPath, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if skipPath(rel, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		parts := strings.Split(rel, "/")
		if len(parts) > 0 {
			topLevelSet[parts[0]] = true
		}
		if info.IsDir() {
			inferFrameworks(rel, frameworkSet)
			return nil
		}
		if lang := extLanguages[strings.ToLower(filepath.Ext(rel))]; lang != "" {
			languageCounts[lang]++
		}
		inferFrameworks(rel, frameworkSet)
		if isSensitivePath(rel) {
			sensitiveSet[rel] = true
		}
		return nil
	})
	if err != nil {
		return artifacts.ProjectProfile{}, fmt.Errorf("walk repo: %w", err)
	}

	return artifacts.ProjectProfile{
		SchemaVersion:  "teecheck.project_profile.v1",
		RunID:          manifest.RunID,
		Repo:           artifacts.RepoRef{URL: manifest.RepoURL, Commit: manifest.Commit, Focus: manifest.Focus},
		Languages:      sortKeysByValue(languageCounts),
		FrameworkHints: sortedSet(frameworkSet),
		TopLevelDirs:   sortedSet(topLevelSet),
		SensitivePaths: sortedSet(sensitiveSet),
		Notes: []string{
			"project profile is heuristic and intended to guide case selection",
			"framework hints come from path and naming patterns, not full build analysis",
		},
	}, nil
}

func skipPath(rel string, isDir bool) bool {
	for _, prefix := range []string{".git", "node_modules", "target", "dist", "build"} {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}

func inferFrameworks(rel string, frameworkSet map[string]bool) {
	lower := strings.ToLower(rel)
	switch {
	case strings.Contains(lower, "enclave"), strings.Contains(lower, "sgx"):
		frameworkSet["sgx"] = true
	case strings.Contains(lower, "optee"), strings.Contains(lower, "trustzone"), strings.Contains(lower, "/ta/"):
		frameworkSet["trustzone"] = true
	case strings.Contains(lower, "rofl"), strings.Contains(lower, "oasis"):
		frameworkSet["oasis-rofl"] = true
	}
	if strings.Contains(lower, "runtime") {
		frameworkSet["runtime-sdk"] = true
	}
	if strings.Contains(lower, "sol") || strings.Contains(lower, "contract") {
		frameworkSet["web3"] = true
	}
}

func isSensitivePath(rel string) bool {
	lower := strings.ToLower(rel)
	for _, keyword := range []string{
		"verify", "attest", "quote", "report", "key", "secret", "state", "tx", "route", "bridge", "caller", "auth",
	} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func sortKeysByValue(counts map[string]int) []string {
	type item struct {
		Key   string
		Count int
	}
	var items []item
	for k, v := range counts {
		items = append(items, item{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	var out []string
	for _, item := range items {
		out = append(out, item.Key)
	}
	return out
}

func sortedSet(values map[string]bool) []string {
	var out []string
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
