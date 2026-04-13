package sinks

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and validates a sink catalog JSON file.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sink catalog %s: %w", path, err)
	}
	var cat Catalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse sink catalog %s: %w", path, err)
	}
	if err := cat.Validate(); err != nil {
		return nil, fmt.Errorf("validate sink catalog %s: %w", path, err)
	}
	return &cat, nil
}

// Validate checks the catalog conforms to the v2 schema.
func (c *Catalog) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version: got %q, want %q", c.SchemaVersion, SchemaVersion)
	}
	if c.Language == "" {
		return fmt.Errorf("language: required")
	}
	if len(c.Groups) == 0 {
		return fmt.Errorf("groups: at least one required")
	}
	seenGroups := map[string]bool{}
	for i, g := range c.Groups {
		if g.ID == "" {
			return fmt.Errorf("groups[%d].id: required", i)
		}
		if seenGroups[g.ID] {
			return fmt.Errorf("groups[%d].id: duplicate %q", i, g.ID)
		}
		seenGroups[g.ID] = true
		if g.Description == "" {
			return fmt.Errorf("groups[%d].description: required", i)
		}
		if len(g.Categories) == 0 {
			return fmt.Errorf("groups[%d].categories: at least one required", i)
		}
		seenCats := map[string]bool{}
		for j, cat := range g.Categories {
			if cat.ID == "" {
				return fmt.Errorf("groups[%d].categories[%d].id: required", i, j)
			}
			if seenCats[cat.ID] {
				return fmt.Errorf("groups[%d].categories[%d].id: duplicate %q in group", i, j, cat.ID)
			}
			seenCats[cat.ID] = true
			if cat.Description == "" {
				return fmt.Errorf("groups[%d].categories[%d].description: required", i, j)
			}
			if err := cat.Match.Validate(); err != nil {
				return fmt.Errorf("groups[%d].categories[%d].match: %w", i, j, err)
			}
		}
	}
	return nil
}

// Validate checks a Match conforms to the schema rules.
func (m Match) Validate() error {
	switch m.Kind {
	case MatchKindSymbol:
		if len(m.Symbols) == 0 {
			return fmt.Errorf("kind=symbol requires symbols[]")
		}
		if len(m.Patterns) > 0 {
			return fmt.Errorf("kind=symbol cannot have patterns[]")
		}
	case MatchKindSyntax:
		if len(m.Patterns) == 0 {
			return fmt.Errorf("kind=syntax requires patterns[]")
		}
		if len(m.Symbols) > 0 {
			return fmt.Errorf("kind=syntax cannot have symbols[]")
		}
	case "":
		return fmt.Errorf("kind: required (symbol or syntax)")
	default:
		return fmt.Errorf("kind: unknown %q (must be symbol or syntax)", m.Kind)
	}
	return nil
}

// LookupGroup returns the Group with the given ID, or an error.
func (c *Catalog) LookupGroup(id string) (*Group, error) {
	for i := range c.Groups {
		if c.Groups[i].ID == id {
			return &c.Groups[i], nil
		}
	}
	return nil, fmt.Errorf("group %q not found", id)
}

// LookupCategory returns the Category with the given group + category ID.
func (c *Catalog) LookupCategory(groupID, categoryID string) (*Category, error) {
	g, err := c.LookupGroup(groupID)
	if err != nil {
		return nil, err
	}
	for i := range g.Categories {
		if g.Categories[i].ID == categoryID {
			return &g.Categories[i], nil
		}
	}
	return nil, fmt.Errorf("category %q in group %q not found", categoryID, groupID)
}

// GroupHeaders returns groups with categories stripped, for the "*" scope.
func (c *Catalog) GroupHeaders() []Group {
	out := make([]Group, len(c.Groups))
	for i, g := range c.Groups {
		out[i] = Group{
			ID:          g.ID,
			Description: g.Description,
			// Categories deliberately omitted
		}
	}
	return out
}
