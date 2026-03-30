package kgpack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/gitnexus"
)

func Run(cfg config.Config) error {
	graphPath, err := resolveGraphInput(cfg)
	if err != nil {
		return err
	}

	export, err := gitnexus.LoadExport(graphPath)
	if err != nil {
		return fmt.Errorf("load GitNexus export: %w", err)
	}

	if cfg.SourcePath != "" {
		export.SourcePath = cfg.SourcePath
	}

	pack := gitnexus.BuildKnowledgePack(graphPath, export, cfg.FocusArea)
	if err := writeJSON(cfg.ReportPath, pack); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.PromptPath) != "" {
		if err := writeMarkdown(cfg.PromptPath, pack); err != nil {
			return err
		}
	}

	fmt.Printf("Loaded GitNexus graph export with %d node(s) and %d edge(s).\n", pack.Source.NodeCount, pack.Source.EdgeCount)
	fmt.Printf("Graph export: %s\n", graphPath)
	fmt.Printf("Knowledge pack: %s\n", cfg.ReportPath)
	if strings.TrimSpace(cfg.PromptPath) != "" {
		fmt.Printf("Prompt pack: %s\n", cfg.PromptPath)
	}
	return nil
}

func resolveGraphInput(cfg config.Config) (string, error) {
	graphPath := strings.TrimSpace(cfg.GraphJSONPath)
	if graphPath == "" {
		if strings.TrimSpace(cfg.SourcePath) == "" {
			return "", fmt.Errorf("kgpack requires a graph export path or a source path")
		}
		graphPath = defaultGraphExportPath(cfg.SourcePath)
	}

	if strings.TrimSpace(cfg.SourcePath) != "" && strings.TrimSpace(cfg.GitNexusSSHTarget) != "" {
		exporter := gitnexus.RemoteExporter{
			SSHTarget:    cfg.GitNexusSSHTarget,
			ScriptPath:   cfg.GitNexusScript,
			GitNexusRoot: cfg.GitNexusRoot,
		}
		exportedPath, err := exporter.ExportGraph(cfg.SourcePath, graphPath)
		if err != nil {
			return "", err
		}
		fmt.Printf("Exported GitNexus graph via %s to %s.\n", cfg.GitNexusSSHTarget, exportedPath)
		return exportedPath, nil
	}

	return graphPath, nil
}

func defaultGraphExportPath(sourcePath string) string {
	base := filepath.Base(filepath.Clean(sourcePath))
	base = sanitizeFileStem(base)
	return filepath.Clean(filepath.Join("reports", base+"-gitnexus-graph.json"))
}

func sanitizeFileStem(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "graph"
	}

	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}

	stem := strings.Trim(b.String(), "-")
	if stem == "" {
		return "graph"
	}
	return stem
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeMarkdown(path string, pack gitnexus.KnowledgePack) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# GitNexus Knowledge Pack\n\n")
	b.WriteString(fmt.Sprintf("Focus: `%s`\n\n", pack.Source.FocusArea))
	b.WriteString(fmt.Sprintf("Graph export: `%s`\n\n", pack.Source.GraphJSON))
	if pack.Source.SourcePath != "" {
		b.WriteString(fmt.Sprintf("Source tree: `%s`\n\n", pack.Source.SourcePath))
	}

	b.WriteString("## Overview\n\n")
	b.WriteString("- " + pack.Overview.GraphSummary + "\n")
	b.WriteString("- " + pack.Overview.FocusSummary + "\n")
	b.WriteString("- " + pack.Overview.HotspotSummary + "\n")
	b.WriteString("- " + pack.Overview.LimitationsNote + "\n")

	b.WriteString("\n## Relevant Files\n\n")
	for _, candidate := range pack.RelevantFiles {
		b.WriteString(fmt.Sprintf("- `%s` (%s) score=%d: %s\n", candidate.Label, candidate.Path, candidate.Score, candidate.Reason))
	}
	if len(pack.RelevantFiles) == 0 {
		b.WriteString("- none\n")
	}

	b.WriteString("\n## Relevant Symbols\n\n")
	for _, candidate := range pack.RelevantSymbols {
		location := candidate.Path
		if location == "" {
			location = candidate.Type
		}
		b.WriteString(fmt.Sprintf("- `%s` (%s) score=%d: %s\n", candidate.Label, location, candidate.Score, candidate.Reason))
	}
	if len(pack.RelevantSymbols) == 0 {
		b.WriteString("- none\n")
	}

	b.WriteString("\n## Audit Questions\n\n")
	for _, question := range pack.AuditQuestions {
		b.WriteString("- " + question + "\n")
	}

	b.WriteString("\n## Analyst Notes\n\n")
	for _, note := range pack.AnalystNotes {
		b.WriteString("- " + note + "\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
