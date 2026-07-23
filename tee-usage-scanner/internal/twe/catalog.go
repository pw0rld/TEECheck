package twe

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog is the in-memory, validated set of TWE entries loaded from disk.
// It is the single entry point the planner, expert, query generator, and
// solver use to reach TWE knowledge.
type Catalog struct {
	byID map[string]Entry
}

// Load reads every *.yml / *.yaml file under dir, validates each entry, and
// returns an indexed catalog. It fails fast: any malformed or contradictory
// entry aborts the load with a path-qualified error, so a broken catalog is
// caught at startup rather than mid-run.
func Load(dir string) (*Catalog, error) {
	paths, err := listCatalogFiles(dir)
	if err != nil {
		return nil, err
	}
	c := &Catalog{byID: make(map[string]Entry)}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var entry Entry
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&entry); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if err := entry.Validate(); err != nil {
			return nil, fmt.Errorf("invalid TWE in %s: %w", path, err)
		}
		if _, dup := c.byID[entry.ID]; dup {
			return nil, fmt.Errorf("duplicate TWE id %q (%s)", entry.ID, path)
		}
		c.byID[entry.ID] = entry
	}
	return c, nil
}

func listCatalogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read catalog dir %s: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yml" || ext == ".yaml" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// Validate checks a single entry against the schema rules. The most
// important rule is that allowed_enums may only constrain roles that are
// actually required — otherwise a typo silently produces an enum that is
// never enforced.
func (e Entry) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("%s: name is required", e.ID)
	}
	if !ValidFamilies[e.Family] {
		return fmt.Errorf("%s: unknown family %q", e.ID, e.Family)
	}
	if strings.TrimSpace(e.Summary) == "" {
		return fmt.Errorf("%s: summary is required", e.ID)
	}
	if len(e.ApplicableContexts) == 0 {
		return fmt.Errorf("%s: applicable_contexts must be non-empty", e.ID)
	}
	if len(e.RequiredTrustIR) == 0 {
		return fmt.Errorf("%s: required_trustir must be non-empty", e.ID)
	}
	required := make(map[string]bool, len(e.RequiredTrustIR))
	for _, role := range e.RequiredTrustIR {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("%s: required_trustir contains an empty role", e.ID)
		}
		if required[role] {
			return fmt.Errorf("%s: duplicate required role %q", e.ID, role)
		}
		required[role] = true
	}
	for role := range e.AllowedEnums {
		if !required[role] {
			return fmt.Errorf("%s: allowed_enums role %q is not in required_trustir", e.ID, role)
		}
		if len(e.AllowedEnums[role]) == 0 {
			return fmt.Errorf("%s: allowed_enums[%q] is empty", e.ID, role)
		}
	}
	if len(e.CodeQLModules) == 0 {
		return fmt.Errorf("%s: codeql_modules must be non-empty", e.ID)
	}
	if strings.TrimSpace(e.ViolationCondition) == "" {
		return fmt.Errorf("%s: violation_condition is required", e.ID)
	}
	return nil
}

// Get returns the entry with the given id, or false if absent.
func (c *Catalog) Get(id string) (Entry, bool) {
	e, ok := c.byID[id]
	return e, ok
}

// All returns every entry, ordered by id for deterministic iteration.
func (c *Catalog) All() []Entry {
	out := make([]Entry, 0, len(c.byID))
	for _, e := range c.byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len reports how many entries the catalog holds.
func (c *Catalog) Len() int { return len(c.byID) }

// ByContext returns the entries whose applicable_contexts include ctx,
// ordered by id. The planner uses this to scope which TWEs to attempt on a
// given site.
func (c *Catalog) ByContext(ctx string) []Entry {
	var out []Entry
	for _, e := range c.All() {
		for _, applicable := range e.ApplicableContexts {
			if applicable == ctx {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ValidateCandidate checks an LLM-produced TrustIRCandidate against its TWE:
// every required role must be present, and every role's enum must be allowed.
// This is workflow step 8 — the deterministic gate that stands between the
// LLM's proposal and the Binder. It returns nil when the candidate is
// admissible.
func (c *Catalog) ValidateCandidate(cand TrustIRCandidate) error {
	entry, ok := c.byID[cand.TWEID]
	if !ok {
		return fmt.Errorf("unknown twe_id %q", cand.TWEID)
	}
	for _, role := range entry.RequiredTrustIR {
		rc, present := cand.Roles[role]
		if !present {
			return fmt.Errorf("%s: missing required role %q", cand.TWEID, role)
		}
		allowed, constrained := entry.AllowedEnums[role]
		if !constrained {
			continue
		}
		if !contains(allowed, rc.Enum) {
			return fmt.Errorf("%s: role %q enum %q not allowed", cand.TWEID, role, rc.Enum)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
