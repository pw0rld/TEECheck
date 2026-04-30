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

		// Load matching hypothesis + memo to drive the structured
		// display. Index alignment mirrors how arbiter wrote them
		// (case-NNN ↔ hypothesis-NNN ↔ verify-NNN).
		var hyp artifacts.Hypothesis
		var memo artifacts.VerificationMemo
		_ = runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hyp)
		_ = runfs.ReadJSON(filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1)), &memo)

		DisplayPacketSummary(output, idx, total, item, packetText)
		DisplayFindingDetail(output, item, hyp, memo)

		verdict := PromptVerdict(scanner, output)
		if verdict == "quit" {
			fmt.Fprintln(output, "Review session ended.")
			break
		}
		if verdict == artifacts.VerdictSkip {
			fmt.Fprintln(output, "Skipped.")
			continue
		}

		// reason_code is asked for every non-TP verdict. TP doesn't
		// need a code (the scanner was right). Skip is filtered above
		// so won't reach here. Reviewers can press enter to leave the
		// code empty if no taxonomy entry fits.
		var reasonCode string
		if verdict != artifacts.VerdictTruePositive {
			reasonCode = PromptReasonCode(scanner, output)
		}
		correctedSeverity := PromptSeverityOverride(scanner, output, item.Severity)
		confidenceOverride := PromptConfidenceOverride(scanner, output, item.Confidence)
		tags := PromptTags(scanner, output)
		notes := PromptNotes(scanner, output)

		record := artifacts.ReviewRecord{
			SchemaVersion:      "teecheck.review_record.v1",
			CaseID:             item.FindingID,
			FindingID:          item.FindingID,
			Verdict:            verdict,
			ReasonCode:         reasonCode,
			CorrectedSeverity:  correctedSeverity,
			ConfidenceOverride: confidenceOverride,
			Tags:               tags,
			Notes:              notes,
			ReviewedAt:         now.Format(time.RFC3339),
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
