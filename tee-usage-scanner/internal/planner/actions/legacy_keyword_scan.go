package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type legacyKeywordScanArgs struct {
	RunDir      string `json:"run_dir"`
	MaxHotspots int    `json:"max_hotspots,omitempty"`
}

// LegacyKeywordScanHandler wraps the existing mapper + hotspots
// chain (the pre-L3 heuristic hotspot picker) into a planner action.
//
// The L3 LLM can call this as a low-cost initial scan that produces
// a hotspot_index.json the LLM then narrows. It is the action-shaped
// mirror of "fall back to heuristic mode if all else fails".
//
// The action expects manifest + graph files to already exist in the
// run directory (the planner's own preprocessor stage writes these
// before the loop starts). mapper.Run internally calls repomap.Run
// which produces repo_map.json, then hotspots.Run reads it.
//
// Config fields actually read by the chain:
//   - cfg.RunDir       — used by repomap + hotspots for manifest, paths
//   - cfg.GraphJSONPath — used by repomap to load the structure graph
//   - cfg.MaxHotspots  — used by hotspots to cap result count
//
// Focus is read from manifest.Focus (loaded from 00_manifest.json),
// so it does NOT need to be set in cfg separately.
type LegacyKeywordScanHandler struct{}

func (LegacyKeywordScanHandler) Name() string { return "legacy_keyword_scan" }

func (LegacyKeywordScanHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args legacyKeywordScanArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("invalid args: %v", err))
	}
	if args.RunDir == "" {
		return fail("legacy_keyword_scan", "run_dir is required")
	}
	if args.MaxHotspots <= 0 {
		args.MaxHotspots = 12
	}

	cfg := config.Config{
		RunDir:        args.RunDir,
		MaxHotspots:   args.MaxHotspots,
		GraphJSONPath: runfs.GraphPath(args.RunDir),
	}

	// mapper.Run internally calls repomap.Run then hotspots.Run, so the
	// full chain — graph → repo_map → hotspot_index — is driven by one call.
	if err := mapper.Run(cfg); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("mapper: %v", err))
	}

	var index artifacts.HotspotIndex
	if err := runfs.ReadJSON(runfs.HotspotIndexPath(args.RunDir), &index); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("read hotspot_index: %v", err))
	}

	return ActionResult{
		Name:   "legacy_keyword_scan",
		OK:     true,
		Output: fmt.Sprintf("legacy keyword scan produced %d hotspots in %s", len(index.Hotspots), runfs.HotspotIndexPath(args.RunDir)),
	}
}

// Ensure LegacyKeywordScanHandler satisfies the Handler interface at compile time.
var _ Handler = LegacyKeywordScanHandler{}
