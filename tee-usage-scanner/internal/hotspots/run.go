package hotspots

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var repoMap artifacts.RepoMap
	if err := runfs.ReadJSON(runfs.RepoMapPath(cfg.RunDir), &repoMap); err != nil {
		return fmt.Errorf("load repo_map: %w", err)
	}

	hotspots := buildHotspots(repoMap, cfg.MaxHotspots)
	index := artifacts.HotspotIndex{
		SchemaVersion: "teecheck.hotspot_index.v1",
		RunID:         manifest.RunID,
		Hotspots:      hotspots,
	}

	if err := runfs.WriteJSON(runfs.HotspotIndexPath(cfg.RunDir), index); err != nil {
		return fmt.Errorf("write hotspot_index: %w", err)
	}

	fmt.Printf("Hotspot index written to %s\n", runfs.HotspotIndexPath(cfg.RunDir))
	return nil
}

func buildHotspots(repoMap artifacts.RepoMap, maxHotspots int) []artifacts.Hotspot {
	result := []artifacts.Hotspot{}
	seen := map[string]bool{}

	for _, boundary := range repoMap.Boundaries {
		key := boundary.Kind + "::" + strings.Join(boundary.Paths, ",") + "::" + strings.Join(boundary.Symbols, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		why := []string{fmt.Sprintf("boundary candidate: %s (%s)", boundary.Kind, boundary.Direction)}
		if boundary.Description != "" {
			why = append(why, boundary.Description)
		}
		result = append(result, artifacts.Hotspot{
			HotspotID:   fmt.Sprintf("hotspot-%03d", len(result)+1),
			Kind:        boundary.Kind,
			Priority:    priorityForBoundary(boundary.Kind),
			Paths:       boundary.Paths,
			Symbols:     boundary.Symbols,
			WhySelected: why,
		})
		if len(result) >= maxHotspots {
			return result
		}
	}

	for _, symbol := range repoMap.ImportantSymbols {
		key := symbol.Path + "::" + symbol.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, artifacts.Hotspot{
			HotspotID:   fmt.Sprintf("hotspot-%03d", len(result)+1),
			Kind:        inferKind(symbol.Path + " " + symbol.Symbol),
			Priority:    fallbackPriority(symbol.Priority),
			Paths:       []string{symbol.Path},
			Symbols:     []string{symbol.Symbol},
			WhySelected: symbol.Reasons,
		})
		if len(result) >= maxHotspots {
			return result
		}
	}

	for _, file := range repoMap.ImportantFiles {
		key := file.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, artifacts.Hotspot{
			HotspotID:   fmt.Sprintf("hotspot-%03d", len(result)+1),
			Kind:        inferKind(file.Path),
			Priority:    fallbackPriority(file.Priority),
			Paths:       []string{file.Path},
			WhySelected: file.Reasons,
		})
		if len(result) >= maxHotspots {
			return result
		}
	}

	return result
}

func inferKind(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "attest") || strings.Contains(lower, "quote") || strings.Contains(lower, "report") || strings.Contains(lower, "verify"):
		return "attestation"
	case strings.Contains(lower, "auth") || strings.Contains(lower, "caller") || strings.Contains(lower, "session"):
		return "authorization"
	case strings.Contains(lower, "state") || strings.Contains(lower, "replay") || strings.Contains(lower, "nonce"):
		return "state_machine"
	case strings.Contains(lower, "key") || strings.Contains(lower, "secret") || strings.Contains(lower, "sign"):
		return "key_management"
	case strings.Contains(lower, "fallback") || strings.Contains(lower, "retry") || strings.Contains(lower, "debug"):
		return "fallback"
	case strings.Contains(lower, "ffi") || strings.Contains(lower, "binding") || strings.Contains(lower, "bridge"):
		return "ffi_boundary"
	default:
		return "boundary"
	}
}

func priorityForBoundary(kind string) string {
	switch kind {
	case "attestation", "authorization", "key_management", "host_interface", "runtime_entry":
		return "high"
	case "state_machine", "ffi_boundary", "fallback":
		return "medium"
	default:
		return "medium"
	}
}

func fallbackPriority(priority string) string {
	if priority == "" {
		return "medium"
	}
	return priority
}
