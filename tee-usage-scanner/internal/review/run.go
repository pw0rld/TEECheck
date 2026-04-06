package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config) error {
	return RunWithIO(cfg, os.Stdin, os.Stdout, time.Now())
}

func RunWithIO(cfg config.Config, input io.Reader, output io.Writer, now time.Time) error {
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	packetPaths, err := filepath.Glob(filepath.Join(runfs.ArbiterPacketsDir(cfg.RunDir), "review-*.md"))
	if err != nil {
		return fmt.Errorf("glob review packets: %w", err)
	}

	scanner := bufio.NewScanner(input)
	total := len(findings.Findings)
	var records []artifacts.ReviewRecord

	for idx, item := range findings.Findings {
		var packetText string
		if idx < len(packetPaths) {
			data, err := os.ReadFile(packetPaths[idx])
			if err == nil {
				packetText = string(data)
			}
		}

		DisplayPacketSummary(output, idx, total, item, packetText)

		verdict := PromptVerdict(scanner, output)
		if verdict == "quit" {
			fmt.Fprintln(output, "Review session ended.")
			break
		}
		if verdict == "skip" {
			fmt.Fprintln(output, "Skipped.")
			continue
		}

		severity := PromptSeverityOverride(scanner, output, item.Severity)
		tags := PromptTags(scanner, output)
		notes := PromptNotes(scanner, output)

		record := artifacts.ReviewRecord{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        item.FindingID,
			FindingID:     item.FindingID,
			Verdict:       verdict,
			Severity:      severity,
			Tags:          tags,
			Notes:         notes,
			ReviewedAt:    now.Format(time.RFC3339),
		}
		records = append(records, record)

		reviewPath := filepath.Join(runfs.ReviewDir(cfg.RunDir), fmt.Sprintf("review-%03d.json", idx+1))
		if err := runfs.WriteJSON(reviewPath, record); err != nil {
			return fmt.Errorf("write review %s: %w", record.CaseID, err)
		}
		fmt.Fprintf(output, "Saved review-%03d.json\n", idx+1)
	}

	if len(records) > 0 {
		jsonlPath := runfs.ReviewRecordsPath(cfg.RunDir)
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open review_records.jsonl: %w", err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("write jsonl record: %w", err)
			}
		}
		fmt.Fprintf(output, "\nWrote %d review record(s) to %s\n", len(records), jsonlPath)
	}

	return nil
}
