package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

type sinkCatalogLookupArgs struct {
	Scope string `json:"scope"`
}

// SinkCatalogLookupHandler implements sink_catalog_lookup. The LLM
// uses three scope levels:
//
//   - "*"               → group headers only (table of contents)
//   - "<group_id>"      → full group with all its categories
//   - "<group_id>.<cat>" → a single category definition
//
// The handler caches the parsed catalog after the first successful
// load. CatalogPath must be set before Run is called; the registry
// helper in registry_with_sinks.go wires this from the knowledge root.
//
// Because the handler holds cached state, callers should register a
// pointer to a single instance, not a value, in the registry.
type SinkCatalogLookupHandler struct {
	CatalogPath string

	// cached catalog after first successful Load
	cached *sinks.Catalog
}

func (h *SinkCatalogLookupHandler) Name() string { return "sink_catalog_lookup" }

func (h *SinkCatalogLookupHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args sinkCatalogLookupArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("sink_catalog_lookup", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Scope) == "" {
		return fail("sink_catalog_lookup", "scope is required (use \"*\", a group id, or group.category)")
	}
	cat, err := h.catalog()
	if err != nil {
		return fail("sink_catalog_lookup", err.Error())
	}

	var payload any
	switch {
	case args.Scope == "*":
		payload = cat.GroupHeaders()
	case strings.Contains(args.Scope, "."):
		parts := strings.SplitN(args.Scope, ".", 2)
		c, err := cat.LookupCategory(parts[0], parts[1])
		if err != nil {
			return fail("sink_catalog_lookup", err.Error())
		}
		payload = c
	default:
		g, err := cat.LookupGroup(args.Scope)
		if err != nil {
			return fail("sink_catalog_lookup", err.Error())
		}
		payload = g
	}

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fail("sink_catalog_lookup", fmt.Sprintf("marshal: %v", err))
	}
	return ActionResult{
		Name:   "sink_catalog_lookup",
		OK:     true,
		Output: string(out),
	}
}

// catalog returns the cached catalog, loading it on first call.
func (h *SinkCatalogLookupHandler) catalog() (*sinks.Catalog, error) {
	if h.cached != nil {
		return h.cached, nil
	}
	cat, err := sinks.Load(h.CatalogPath)
	if err != nil {
		return nil, err
	}
	h.cached = cat
	return cat, nil
}
