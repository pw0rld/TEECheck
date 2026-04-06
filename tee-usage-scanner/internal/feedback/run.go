package feedback

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config, w io.Writer) error {
	// Load findings to get summary information
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	// Load review records
	reviewRecords, err := loadReviewRecords(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load review records: %w", err)
	}

	if len(reviewRecords) == 0 {
		fmt.Fprintf(w, "No review records found in %s\n", cfg.RunDir)
		return nil
	}

	// Archive findings and collect wiki suggestions
	var wikiSuggestions []string
	for _, record := range reviewRecords {
		// Find the corresponding finding
		var finding *artifacts.FindingItem
		for i := range findings.Findings {
			if findings.Findings[i].FindingID == record.FindingID {
				finding = &findings.Findings[i]
				break
			}
		}
		if finding == nil {
			continue
		}

		// Determine category and archive
		var category string
		if record.Verdict == "confirmed" || record.Verdict == "confirmed_via_patch" {
			category = "true-positive"
		} else if record.Verdict == "dismissed" || record.Verdict == "false_alarm" {
			category = "false-positive"
		} else {
			continue
		}

		// Archive the finding
		if err := archiveFinding(cfg.KnowledgeRoot, category, record, finding); err != nil {
			fmt.Fprintf(w, "Warning: failed to archive %s: %v\n", record.FindingID, err)
			continue
		}

		// Generate wiki suggestion
		suggestion := generateWikiSuggestion(category, record, finding)
		wikiSuggestions = append(wikiSuggestions, suggestion)
	}

	// Write wiki suggestions
	if len(wikiSuggestions) > 0 {
		fmt.Fprintf(w, "\n=== Wiki Suggestions ===\n")
		for i, sugg := range wikiSuggestions {
			fmt.Fprintf(w, "\n[%d] %s\n", i+1, sugg)
		}
		fmt.Fprintf(w, "\nAppended %d wiki suggestions to knowledge base.\n", len(wikiSuggestions))
	}

	return nil
}

func loadReviewRecords(runDir string) ([]artifacts.ReviewRecord, error) {
	jsonlPath := runfs.ReviewRecordsPath(runDir)
	f, err := os.Open(jsonlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var records []artifacts.ReviewRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var record artifacts.ReviewRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("parse review record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func archiveFinding(knowledgeRoot, category string, record artifacts.ReviewRecord, finding *artifacts.FindingItem) error {
	archiveDir := filepath.Join(knowledgeRoot, "learned", category)
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		return err
	}

	archivePath := filepath.Join(archiveDir, record.FindingID+".md")
	content := formatArchiveContent(record, finding)
	return os.WriteFile(archivePath, []byte(content), 0o644)
}

func formatArchiveContent(record artifacts.ReviewRecord, finding *artifacts.FindingItem) string {
	var content string
	content += fmt.Sprintf("# %s\n\n", record.FindingID)
	content += fmt.Sprintf("**Summary**: %s\n\n", finding.Summary)
	content += fmt.Sprintf("**Verdict**: %s\n", record.Verdict)
	content += fmt.Sprintf("**Severity**: %s\n", record.Severity)
	if len(record.Tags) > 0 {
		content += fmt.Sprintf("**Tags**: %v\n", record.Tags)
	}
	if record.Notes != "" {
		content += fmt.Sprintf("**Notes**: %s\n", record.Notes)
	}
	if len(finding.Files) > 0 {
		content += fmt.Sprintf("**Files**: %v\n", finding.Files)
	}
	content += fmt.Sprintf("\nReviewed at: %s\n", record.ReviewedAt)
	return content
}

func generateWikiSuggestion(category string, record artifacts.ReviewRecord, finding *artifacts.FindingItem) string {
	var prefix string
	if category == "true-positive" {
		prefix = "TP"
	} else {
		prefix = "FP"
	}

	suggestion := fmt.Sprintf(
		"[%s] %s: %s (severity: %s, tags: %v)",
		prefix,
		record.FindingID,
		finding.Summary,
		record.Severity,
		record.Tags,
	)

	if record.Notes != "" {
		suggestion += fmt.Sprintf(" - %s", record.Notes)
	}

	return suggestion
}
