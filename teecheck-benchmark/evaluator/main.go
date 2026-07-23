package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/judge"
	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/llm"
	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/rag"
)

func main() {
	batch := flag.Bool("batch", false, "scan and evaluate every vulnerable/fixed dataset pair")
	reportPath := flag.String("report", "", "scanner findings.json")
	casesDir := flag.String("cases", "datasets", "benchmark datasets")
	outPath := flag.String("out", "", "judgment JSON output")
	baseURL := flag.String("base-url", env("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"), "OpenAI-compatible API base URL")
	model := flag.String("model", env("LLM_MODEL", env("TEECHECK_LLM_MODEL", "glm-4.5")), "LLM model")
	apiKey := flag.String("api-key", env("GLM_API_KEY", env("ZAI_API_KEY", env("TEECHECK_LLM_API_KEY", ""))), "LLM API key")
	topK := flag.Int("top-k", 5, "number of retrieved cases per finding")
	scannerCommand := flag.String("scanner-command", "", "scanner command template with {input}, {run_dir}, {case}, and {variant}")
	resultsDir := flag.String("results", "results/llm", "batch result directory")
	timeout := flag.Duration("timeout", 30*time.Minute, "scanner timeout per variant")
	flag.Parse()
	if *batch {
		if *scannerCommand == "" {
			fatal("-batch requires -scanner-command")
		}
		if err := runBatch(*casesDir, *resultsDir, *scannerCommand, *timeout, *baseURL, *apiKey, *model, *topK); err != nil {
			fatal(err.Error())
		}
		return
	}
	if *reportPath == "" {
		fatal("-report is required")
	}
	reportBytes, err := os.ReadFile(*reportPath)
	if err != nil {
		fatal(err.Error())
	}
	var report rag.Report
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		fatal(err.Error())
	}
	cases, err := rag.Load(*casesDir)
	if err != nil {
		fatal(err.Error())
	}
	client := llm.Client{BaseURL: *baseURL, APIKey: *apiKey, Model: *model}
	var decisions []judge.Decision
	for _, finding := range report.Findings {
		hits := rag.Retrieve(cases, rag.Report{RunID: report.RunID, Findings: []rag.Finding{finding}}, *topK)
		for _, hit := range hits {
			prompt, err := judge.Prompt(rag.Report{RunID: report.RunID, Findings: []rag.Finding{finding}}, hit)
			if err != nil {
				fatal(err.Error())
			}
			// One bad LLM response must not abort the whole run: record the
			// failure on the decision and continue, so a single 429 or a
			// malformed judgment does not discard every other result.
			decision := judge.Decision{CaseID: hit.CaseID}
			answer, err := client.Complete(context.Background(), prompt)
			if err != nil {
				decision.Reason = "judge error: " + err.Error()
			} else if err := decodeJSON(answer, &decision); err != nil {
				decision.CaseID = hit.CaseID
				decision.Reason = "judge output parse error: " + err.Error()
			}
			if decision.CaseID == "" {
				decision.CaseID = hit.CaseID
			}
			decisions = append(decisions, decision)
		}
	}
	out := struct {
		ReportPath string           `json:"report_path"`
		Decisions  []judge.Decision `json:"decisions"`
	}{*reportPath, decisions}
	b, _ := json.MarshalIndent(out, "", "  ")
	b = append(b, '\n')
	if *outPath == "" {
		fmt.Print(string(b))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(*outPath, b, 0o644); err != nil {
		fatal(err.Error())
	}
}

func decodeJSON(s string, dst any) error {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	return json.Unmarshal([]byte(strings.TrimSpace(s)), dst)
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func fatal(msg string) { fmt.Fprintln(os.Stderr, msg); os.Exit(1) }
