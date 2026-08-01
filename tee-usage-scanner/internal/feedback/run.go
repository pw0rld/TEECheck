package feedback

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

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
	content += fmt.Sprintf("**Severity**: %s\n", record.EffectiveSeverity())
	if record.ConfidenceOverride != "" {
		content += fmt.Sprintf("**Confidence**: %s\n", record.ConfidenceOverride)
	}
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

func RunWithBus(cfg config.Config, client llm.Client, w io.Writer, bus *agentbus.Bus) error {
	records, err := loadReviewRecords(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load review records: %w", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(w, "No review records found.")
		return nil
	}

	var findings artifacts.Findings
	findingsMap := make(map[string]artifacts.FindingItem)
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err == nil {
		for _, f := range findings.Findings {
			findingsMap[f.FindingID] = f
		}
	}

	pages, _ := knowledge.LoadPages(cfg.KnowledgeRoot)
	pageSummary := formatPageSummaries(pages)

	archived := 0
	for idx, rec := range records {
		finding := findingsMap[rec.FindingID]

		bus.ResetDialog(rec.CaseID)
		result, err := curateLLM(context.Background(), client, bus, rec, finding, pageSummary, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			fmt.Fprintf(w, "Warning: curator LLM failed for %s: %v, falling back to deterministic archive\n", rec.CaseID, err)
			category := verdictToCategory(rec.Verdict)
			archiveFinding(cfg.KnowledgeRoot, category, rec, &finding)
			archived++
			continue
		}

		category := verdictToCategory(rec.Verdict)
		archiveDir := filepath.Join(cfg.KnowledgeRoot, "learned", category)
		if err := os.MkdirAll(archiveDir, 0o755); err != nil {
			return err
		}
		archivePath := filepath.Join(archiveDir, curatorSanitize(rec.FindingID)+".md")
		if err := os.WriteFile(archivePath, []byte(result.ArchiveContent), 0o644); err != nil {
			return fmt.Errorf("write archive: %w", err)
		}
		archived++

		for _, update := range result.WikiUpdates {
			if update.Action == "append" {
				fullPath := filepath.Join(cfg.KnowledgeRoot, update.PagePath)
				f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_APPEND, 0o644)
				if err != nil {
					fmt.Fprintf(w, "Warning: could not append to %s: %v\n", update.PagePath, err)
					continue
				}
				f.WriteString("\n" + update.Content + "\n")
				f.Close()
				fmt.Fprintf(w, "Appended to %s: %s\n", update.PagePath, update.Reason)
			} else {
				fmt.Fprintf(w, "Suggest new wiki page: %s — %s\n", update.PagePath, update.Reason)
			}
		}

		if dialog := bus.GetDialog(rec.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.CuratorDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := curatorWriteDialog(dialogPath, dialog); err != nil {
				fmt.Fprintf(w, "Warning: failed to write curator dialog: %v\n", err)
			}
		}
	}

	fmt.Fprintf(w, "\nArchived %d review record(s) to %s/learned/\n", archived, cfg.KnowledgeRoot)
	return nil
}

type curatorResult struct {
	ArchiveContent string
	WikiUpdates    []wikiUpdate
}

type wikiUpdate struct {
	Action   string `json:"action"`
	PagePath string `json:"page_path"`
	Content  string `json:"content"`
	Reason   string `json:"reason"`
}

func curateLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, rec artifacts.ReviewRecord, finding artifacts.FindingItem, pageSummary string, agentID string, temperature float64) (curatorResult, error) {
	systemPrompt := `You are the Curator Agent in TEECheck. Your role is to maintain the knowledge base from human review outcomes. You can ask other agents about their reasoning.

Return a JSON object with fields:
- archive_content: string (markdown for the learned/ archive page)
- wiki_updates: array of objects, each with: action ("append"|"suggest_new"), page_path (string), content (string), reason (string)
- queries: array of objects (optional, each with: to_agent, kind, question)`

	// An empty ConfidenceOverride means the reviewer pressed enter to
	// keep the agent's confidence, which is a different statement
	// from "the reviewer said nothing" — say so rather than emitting
	// a blank field the model has to guess about.
	confidence := rec.ConfidenceOverride
	if confidence == "" {
		confidence = "(reviewer kept the agent value)"
	}

	userMsg := fmt.Sprintf(`Review record:
- Case: %s
- Verdict: %s
- Severity: %s
- Confidence: %s
- Tags: %s
- Notes: %s
- Reviewed at: %s

Finding context:
- Summary: %s
- Status: %s
- Files: %s
- Evidence: %s

Existing wiki pages:
%s`,
		rec.CaseID, rec.Verdict, rec.EffectiveSeverity(),
		confidence,
		strings.Join(rec.Tags, ", "), rec.Notes, rec.ReviewedAt,
		finding.Summary, finding.Status,
		strings.Join(finding.Files, ", "),
		strings.Join(finding.Evidence, " | "),
		pageSummary)

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
			JSONMode:     true,
		})
		if err != nil {
			return curatorResult{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			ArchiveContent string       `json:"archive_content"`
			WikiUpdates    []wikiUpdate `json:"wiki_updates"`
			Queries        []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return curatorResult{}, fmt.Errorf("parse curator json: %w | raw=%s", err, curatorTruncate(resp.Text, 400))
		}

		if len(parsed.Queries) == 0 {
			return curatorResult{
				ArchiveContent: parsed.ArchiveContent,
				WikiUpdates:    parsed.WikiUpdates,
			}, nil
		}

		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, rec.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("curator-%s-r%d-q%d", rec.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
				// The curator's bus agents get the human verdict and the
				// finding it was passed on. They have no file access, and
				// agentbus refuses a query with nothing to reason from.
				Evidence: curatorBusEvidence(rec, finding),
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s", busResp.FromAgent, busResp.Answer))
		}

		followUp := fmt.Sprintf("Here are the responses:\n%s\n\nNow provide your final output.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	return curatorResult{}, fmt.Errorf("reached maximum dialog rounds without curator output")
}

func formatPageSummaries(pages []knowledge.Page) string {
	if len(pages) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, p := range pages {
		lines = append(lines, fmt.Sprintf("  - %s [%s] tags: %s", p.Title, p.Path, strings.Join(p.Tags, ",")))
	}
	return strings.Join(lines, "\n")
}

func verdictToCategory(verdict string) string {
	switch artifacts.NormalizeVerdict(verdict) {
	case artifacts.VerdictTruePositive:
		return "true-positive"
	case artifacts.VerdictFalsePositive:
		return "false-positive"
	default:
		return "review-memory"
	}
}

func curatorSanitize(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "@", "_")
	return r.Replace(s)
}

func curatorWriteDialog(path string, dialog *agentbus.Dialog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, round := range dialog.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	return nil
}

func curatorTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// curatorBusEvidence renders what a bus agent may reason from during
// curation: the human's verdict and the finding it applies to. A bus agent
// has no file access and no tools, so this is the whole of its world.
func curatorBusEvidence(rec artifacts.ReviewRecord, finding artifacts.FindingItem) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Case %s / finding %s\n", rec.CaseID, rec.FindingID)
	fmt.Fprintf(&b, "human verdict: %s (severity %s)\n", rec.Verdict, rec.EffectiveSeverity())
	if rec.Notes != "" {
		fmt.Fprintf(&b, "reviewer notes: %s\n", rec.Notes)
	}
	fmt.Fprintf(&b, "\nFinding status: %s\nsummary: %s\n", finding.Status, finding.Summary)
	if len(finding.Files) > 0 {
		fmt.Fprintf(&b, "files: %s\n", strings.Join(finding.Files, ", "))
	}
	for _, e := range finding.Evidence {
		fmt.Fprintf(&b, "- %s\n", e)
	}
	return b.String()
}
