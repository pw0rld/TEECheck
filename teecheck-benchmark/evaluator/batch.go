package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/judge"
	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/llm"
	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/rag"
)

type batchResult struct {
	CaseID       string           `json:"case_id"`
	Variant      string           `json:"variant"`
	Decisions    []judge.Decision `json:"decisions"`
	FindingsPath string           `json:"findings_path"`
	Error        string           `json:"error,omitempty"`
}

func runBatch(casesDir, resultsDir, template string, timeout time.Duration, baseURL, apiKey, model string, topK int) error {
	cases, err := rag.Load(casesDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return err
	}
	client := llm.Client{BaseURL: baseURL, APIKey: apiKey, Model: model}
	var all []batchResult
	for _, c := range cases {
		for _, variant := range []string{"vulnerable", "fixed"} {
			runDir := filepath.Join(resultsDir, c.ID, variant)
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				return err
			}
			input, _ := filepath.Abs(filepath.Join(casesDir, c.ID, variant))
			absRun, _ := filepath.Abs(runDir)
			cmdline := expandBatchCommand(template, map[string]string{"input": input, "run_dir": absRun, "case": c.ID, "variant": variant})
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			cmd := exec.CommandContext(ctx, "sh", "-c", cmdline)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("SCAN %s/%s\n", c.ID, variant)
			r := batchResult{CaseID: c.ID, Variant: variant}
			runErr := cmd.Run()
			cancel()
			findingsPath, findErr := findBatchFindings(runDir)
			if ctx.Err() != nil {
				r.Error = ctx.Err().Error()
			} else if runErr != nil {
				r.Error = runErr.Error()
			} else if findErr != nil {
				r.Error = findErr.Error()
			}
			if r.Error == "" {
				r.FindingsPath = findingsPath
				var report rag.Report
				b, _ := os.ReadFile(findingsPath)
				if err := json.Unmarshal(b, &report); err != nil {
					r.Error = err.Error()
				} else {
					for _, f := range report.Findings {
						for _, hit := range rag.Retrieve(cases, rag.Report{RunID: report.RunID, Findings: []rag.Finding{f}}, topK) {
							prompt, err := judge.Prompt(rag.Report{RunID: report.RunID, Findings: []rag.Finding{f}}, hit)
							if err != nil {
								r.Error = err.Error()
								break
							}
							answer, err := client.Complete(context.Background(), prompt)
							if err != nil {
								r.Error = err.Error()
								break
							}
							var d judge.Decision
							if err := decodeJSON(answer, &d); err != nil {
								r.Error = err.Error()
								break
							}
							if d.CaseID == "" {
								d.CaseID = hit.CaseID
							}
							d.Variant = variant
							r.Decisions = append(r.Decisions, d)
						}
					}
				}
			}
			all = append(all, r)
			b, _ := json.MarshalIndent(r, "", "  ")
			_ = os.WriteFile(filepath.Join(runDir, "judgments.json"), append(b, '\n'), 0o644)
		}
	}
	b, _ := json.MarshalIndent(struct {
		Results []batchResult `json:"results"`
	}{all}, "", "  ")
	return os.WriteFile(filepath.Join(resultsDir, "batch-results.json"), append(b, '\n'), 0o644)
}

func expandBatchCommand(template string, values map[string]string) string {
	out := template
	for k, v := range values {
		out = strings.ReplaceAll(out, "{"+k+"}", "'"+strings.ReplaceAll(v, "'", "'\\''")+"'")
	}
	return out
}

func findBatchFindings(root string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "findings.json" {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no findings.json under %s", root)
	}
	return found, nil
}
