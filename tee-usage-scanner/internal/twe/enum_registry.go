package twe

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnumRegistry is the migrated tee-audit trustir/spec/enum_registry.yml: the
// fact vocabulary (§5.3 of the merge design) — category name (e.g.
// state_object_kind, authority_kind) to its finite set of allowed values.
// This is a plain map, not a fixed struct, because the category list itself
// grows as new TWE families gain fact extraction support; the categories are
// not enumerated in Go so that adding one is a pure data change.
//
// This type has exactly one construction path — LoadEnumRegistry reading
// knowledge/twe/definitions/enum_registry.yml — because the whole point of
// migrating this file is that the annotation prompt (future work) and the
// fixed-query layer (PR-05) both resolve category values through the same
// loaded map instead of each hard-coding its own copy.
type EnumRegistry map[string][]string

// LoadEnumRegistry reads and validates the fact vocabulary at path
// (knowledge/twe/definitions/enum_registry.yml).
func LoadEnumRegistry(path string) (EnumRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var reg EnumRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := reg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid enum registry in %s: %w", path, err)
	}
	return reg, nil
}

// Validate rejects an empty category, an empty value, and a duplicate value
// within a category — the last of which is exactly the class of typo that
// produces a value the annotation prompt can emit but the query layer never
// recognizes, or vice versa.
func (r EnumRegistry) Validate() error {
	if len(r) == 0 {
		return fmt.Errorf("registry has no categories")
	}
	for category, values := range r {
		if strings.TrimSpace(category) == "" {
			return fmt.Errorf("registry has an empty category name")
		}
		if len(values) == 0 {
			return fmt.Errorf("%s: has no values", category)
		}
		seen := make(map[string]bool, len(values))
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("%s: contains an empty value", category)
			}
			if seen[v] {
				return fmt.Errorf("%s: duplicate value %q", category, v)
			}
			seen[v] = true
		}
	}
	return nil
}

// Categories returns the registry's category names, sorted, for deterministic
// iteration (error messages, generated prompts, etc.).
func (r EnumRegistry) Categories() []string {
	out := make([]string, 0, len(r))
	for category := range r {
		out = append(out, category)
	}
	sort.Strings(out)
	return out
}
