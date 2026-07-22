package twe

import (
	"fmt"
	"os"
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
