package twe

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var definitionIDPattern = regexp.MustCompile(`^TWE-[A-Z0-9-]+$`)

// Definition is one TWE catalog entry migrated from tee-audit's
// trustir/spec/twe_catalog.yml (knowledge/twe/definitions/catalog.yml). It is
// the third TWE shape this package and internal/twecontext carry, deliberately
// narrower than both of the others:
//
//   - Entry (this file's sibling, catalog.go) additionally encodes an
//     executable obligation — allowed_enums, violation_condition,
//     accepted_suppressors — for the retired Go-template query generator.
//   - Playbook (internal/twecontext) additionally encodes the experience
//     narrative — scenario, investigation_steps, common_false_positives —
//     for the reasoning agents.
//
// A Definition is just the fixed id/name/family/query-module anchor both of
// those layers, and the future fact/query layer (PR-05), key off by TWE id.
// Only one Definition — TWE-STATE-001, "Sealed State Restored Without
// Version or Epoch Continuity" — has a Playbook today.
//
// The numeric ids come from tee-audit and are load-bearing: its CodeQL query
// blueprints reference them 207 times across 60 queries, in @id and @tags. So
// the catalog's scheme wins over the readable ids the design doc's examples
// once used, and everything keys off one id per weakness.
type Definition struct {
	ID              string   `yaml:"id"`
	Family          Family   `yaml:"family"`
	Name            string   `yaml:"name"`
	RequiredTrustIR []string `yaml:"required_trustir"`
}

// definitionFile mirrors catalog.yml's single top-level `twe:` list. Unlike
// Entry, which is one file per TWE, the tee-audit catalog format keeps all 16
// definitions in one document — that shape is preserved on migration rather
// than split apart, so a diff against the tee-audit original stays legible.
type definitionFile struct {
	TWE []Definition `yaml:"twe"`
}

// LoadDefinitions reads and validates the TWE definition catalog at path
// (knowledge/twe/definitions/catalog.yml). It fails fast on any malformed,
// duplicate, or family-mismatched entry, and on any field the catalog format
// does not declare — an unrecognized field silently dropped here would be an
// unrecognized field silently dropped everywhere the catalog feeds.
func LoadDefinitions(path string) ([]Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var file definitionFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(file.TWE) == 0 {
		return nil, fmt.Errorf("%s: twe list is empty", path)
	}
	seen := make(map[string]bool, len(file.TWE))
	for _, d := range file.TWE {
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("invalid definition in %s: %w", path, err)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("%s: duplicate TWE id %q", path, d.ID)
		}
		seen[d.ID] = true
	}
	return file.TWE, nil
}

// Validate checks a single Definition.
//
// It no longer requires query_modules: that field named a .ql file per entry,
// was validated non-empty, and was read by nothing else — while all twenty
// distinct filenames across the nineteen entries pointed at queries that
// exist only in the sibling tee-audit rust/javascript/go trees. Validating
// the presence of a value that was never once correct bought nothing and
// forced the wrong list to be maintained. The real binding from a TWE to an
// executable query is trustirfacts.OperationForTWE, checked in both
// directions against the query registry.
func (d Definition) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if !definitionIDPattern.MatchString(d.ID) {
		return fmt.Errorf("%s: id must match %s", d.ID, definitionIDPattern)
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("%s: name is required", d.ID)
	}
	if !ValidFamilies[d.Family] {
		return fmt.Errorf("%s: unknown family %q", d.ID, d.Family)
	}
	if len(d.RequiredTrustIR) == 0 {
		return fmt.Errorf("%s: required_trustir must be non-empty", d.ID)
	}
	seenRole := make(map[string]bool, len(d.RequiredTrustIR))
	for _, role := range d.RequiredTrustIR {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("%s: required_trustir contains an empty role", d.ID)
		}
		if seenRole[role] {
			return fmt.Errorf("%s: duplicate required role %q", d.ID, role)
		}
		seenRole[role] = true
	}
	return nil
}
