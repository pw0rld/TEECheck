package twe

import (
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExclusionRules is the migrated tee-audit trustir/spec/exclusion.yml: glob
// patterns matched against a repo-relative file path to keep vendored
// dependencies, generated code, and build output out of fact extraction and
// LLM classification. See knowledge/twe/definitions/exclusion.yml for why
// each glob exists — it is preserved verbatim from tee-audit rather than
// repeated here.
type ExclusionRules struct {
	DenyGlobs []string `yaml:"deny_globs"`
}

// LoadExclusionRules reads and validates the exclusion globs at path
// (knowledge/twe/definitions/exclusion.yml).
func LoadExclusionRules(path string) (ExclusionRules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ExclusionRules{}, fmt.Errorf("read %s: %w", path, err)
	}
	var rules ExclusionRules
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&rules); err != nil {
		return ExclusionRules{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := rules.Validate(); err != nil {
		return ExclusionRules{}, fmt.Errorf("invalid exclusion rules in %s: %w", path, err)
	}
	return rules, nil
}

// Validate rejects an empty rule set and an empty glob — an accidentally
// empty deny_globs would silently stop excluding vendor/generated paths
// rather than fail loudly.
func (r ExclusionRules) Validate() error {
	if len(r.DenyGlobs) == 0 {
		return fmt.Errorf("deny_globs must be non-empty")
	}
	seen := make(map[string]bool, len(r.DenyGlobs))
	for _, glob := range r.DenyGlobs {
		if strings.TrimSpace(glob) == "" {
			return fmt.Errorf("deny_globs contains an empty glob")
		}
		if seen[glob] {
			return fmt.Errorf("deny_globs contains duplicate glob %q", glob)
		}
		seen[glob] = true
	}
	return nil
}

// Match reports whether rel — a slash-separated, repo-relative file path —
// falls under any deny glob. This is the single evaluator for exclusion.yml;
// callers outside this package (PR-03 fingerprinting, PR-05 fact extraction)
// use it instead of hand-rolling their own vendor/generated/test path lists,
// per docs/history/TEECHECK_TEE_AUDIT_MERGE.zh-CN.md §21: "vendor/generated/test
// scope must be explicitly marked, using the migrated exclusion.yml".
func (r ExclusionRules) Match(rel string) bool {
	rel = strings.TrimPrefix(strings.TrimPrefix(rel, "./"), "/")
	for _, glob := range r.DenyGlobs {
		if matchDoubleStarGlob(glob, rel) {
			return true
		}
	}
	return false
}

// matchDoubleStarGlob matches a "**"-aware glob against a slash-separated
// path. "**" matches zero or more whole path segments; any other segment is
// matched with path.Match (shell-style single-segment wildcards). The
// standard library's path/filepath.Match has no "**" support, and the
// deny_globs in exclusion.yml rely on it (e.g. "**/vendor/**"), so this small
// segment-recursive matcher is needed rather than a library dependency.
func matchDoubleStarGlob(pattern, name string) bool {
	return matchGlobSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchGlobSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		if matchGlobSegments(pattern[1:], name) {
			return true
		}
		if len(name) == 0 {
			return false
		}
		return matchGlobSegments(pattern, name[1:])
	}
	if len(name) == 0 {
		return false
	}
	if ok, err := path.Match(pattern[0], name[0]); err != nil || !ok {
		return false
	}
	return matchGlobSegments(pattern[1:], name[1:])
}
