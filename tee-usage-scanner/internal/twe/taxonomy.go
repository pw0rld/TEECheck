package twe

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FamilyDescription is one family's entry in taxonomy.yml: the human-readable
// definition of what the family covers and which CodeQL strategy shape its
// queries take.
type FamilyDescription struct {
	Name           string `yaml:"name"`
	Definition     string `yaml:"definition"`
	CodeQLStrategy string `yaml:"codeql_strategy"`
}

// Taxonomy is the migrated tee-audit trustir/spec/taxonomy.yml: the seven TWE
// families plus the two ancillary vocabularies (tee_dimensions,
// trust_contexts) tee-audit's fingerprinting and dossier stages use to
// classify a repository. Family keys decode straight into this package's
// Family type so a stray or misspelled family fails to parse rather than
// silently becoming an eighth, unrecognized one.
type Taxonomy struct {
	Families      map[Family]FamilyDescription `yaml:"families"`
	TEEDimensions []string                     `yaml:"tee_dimensions"`
	TrustContexts []string                     `yaml:"trust_contexts"`
}

// LoadTaxonomy reads and validates the family taxonomy at path
// (knowledge/twe/definitions/taxonomy.yml).
func LoadTaxonomy(path string) (Taxonomy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Taxonomy{}, fmt.Errorf("read %s: %w", path, err)
	}
	var t Taxonomy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return Taxonomy{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := t.Validate(); err != nil {
		return Taxonomy{}, fmt.Errorf("invalid taxonomy in %s: %w", path, err)
	}
	return t, nil
}

// Validate checks that taxonomy.yml's family set is exactly ValidFamilies —
// the same seven values internal/twe.Family declares — and that every
// description is populated. §20.1 of the merge design requires this
// correspondence to hold; a taxonomy that adds, drops, or renames a family
// relative to types.go is a defect in one side or the other, not something to
// paper over by loading the extra or missing family anyway.
func (t Taxonomy) Validate() error {
	if len(t.Families) != len(ValidFamilies) {
		return fmt.Errorf("families has %d entries, want %d (one per internal/twe.Family)", len(t.Families), len(ValidFamilies))
	}
	for family := range ValidFamilies {
		desc, ok := t.Families[family]
		if !ok {
			return fmt.Errorf("families is missing %q, which internal/twe.Family declares", family)
		}
		if strings.TrimSpace(desc.Name) == "" {
			return fmt.Errorf("families[%q].name is required", family)
		}
		if strings.TrimSpace(desc.Definition) == "" {
			return fmt.Errorf("families[%q].definition is required", family)
		}
		if strings.TrimSpace(desc.CodeQLStrategy) == "" {
			return fmt.Errorf("families[%q].codeql_strategy is required", family)
		}
	}
	for family := range t.Families {
		if !ValidFamilies[family] {
			return fmt.Errorf("families has %q, which internal/twe.Family does not declare", family)
		}
	}
	if len(t.TEEDimensions) == 0 {
		return fmt.Errorf("tee_dimensions must be non-empty")
	}
	if len(t.TrustContexts) == 0 {
		return fmt.Errorf("trust_contexts must be non-empty")
	}
	return nil
}
