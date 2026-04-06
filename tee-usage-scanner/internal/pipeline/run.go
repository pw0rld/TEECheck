package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	scanall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func Run(cfg config.Config) (string, error) {
	// === Repo Acquisition ===
	fetch, err := repofetch.Fetch(cfg.Target)
	if err != nil {
		return "", fmt.Errorf("fetch repo: %w", err)
	}
	if fetch.Cloned {
		fmt.Printf("Cloned %s to %s (commit: %s)\n", fetch.RepoURL, fetch.LocalPath, truncate(fetch.Commit, 12))
	} else {
		fmt.Printf("Using local repo at %s (commit: %s)\n", fetch.LocalPath, truncate(fetch.Commit, 12))
	}

	cfg.LocalPath = fetch.LocalPath
	cfg.Commit = fetch.Commit
	if fetch.RepoURL != "" {
		cfg.RepoURL = fetch.RepoURL
	} else {
		cfg.RepoURL = fetch.LocalPath
	}

	// === Init Run ===
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return "", fmt.Errorf("ensure knowledge layout: %w", err)
	}
	initCfg := cfg
	initCfg.Command = "init-run"
	runDir, err := runinit.Run(initCfg, time.Now())
	if err != nil {
		return "", fmt.Errorf("init run: %w", err)
	}

	stageCfg := cfg
	stageCfg.RunDir = runDir

	// === Agent 1: Scanner ===
	fmt.Println("\n=== Scanner Agent ===")

	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}

	graphReg := scanall.NewDefaultGraphRegistry()
	graphResult, err := scanner.Scan(context.Background(), graphReg, scanner.ScanRequest{
		RepoRoot: fetch.LocalPath,
		Focus:    cfg.Focus,
		Mode:     cfg.Mode,
	})
	if err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}
	graphPath := runfs.GraphPath(runDir)
	if err := runfs.WriteJSON(graphPath, graphResult); err != nil {
		return "", fmt.Errorf("write graph: %w", err)
	}
	fmt.Printf("Graph generated: %d nodes, %d edges\n", len(graphResult.Nodes), len(graphResult.Edges))

	stageCfg.GraphJSONPath = graphPath
	if err := mapper.Run(stageCfg); err != nil {
		return "", fmt.Errorf("mapper: %w", err)
	}

	if err := cases.Run(stageCfg); err != nil {
		return "", fmt.Errorf("cases: %w", err)
	}

	stageCfg.AgentID = "scanner-001"
	if err := expert.Run(stageCfg); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	// === Agent 2: Reviewer ===
	fmt.Println("\n=== Reviewer Agent ===")

	needsBus := strings.EqualFold(cfg.Mode, "llm")

	if needsBus {
		bus := buildPipelineBus(cfg)

		scReg := scall.NewDefaultRegistry()
		bus.Register("scanner-001", agentbus.NewToolHandler("scanner", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
			req := staticcheck.CheckRequest{
				RepoRoot: fetch.LocalPath,
				Keywords: strings.Fields(q.Question),
			}
			findings, runErr := scReg.RunAll(ctx, req)
			if runErr != nil {
				return agentbus.Response{}, runErr
			}
			var facts []string
			for _, f := range findings {
				facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
			}
			return agentbus.Response{
				QueryID:   q.QueryID,
				FromAgent: "scanner-001",
				Answer:    fmt.Sprintf("Found %d results", len(findings)),
				Facts:     facts,
			}, nil
		}))

		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	} else {
		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.Run(stageCfg); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.Run(stageCfg); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	}

	// Print summary
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err == nil {
		fmt.Printf("\n=== Complete ===\nRun: %s\nFindings: %d\n", runDir, len(findings.Findings))
		for _, f := range findings.Findings {
			fmt.Printf("  [%s] %s — %s (confidence: %s)\n", f.Severity, f.FindingID, f.Status, f.Confidence)
		}
	}

	return runDir, nil
}

func buildPipelineBus(cfg config.Config) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)

	client := llm.NewClient(cfg)
	bus.Register("expert-001", agentbus.NewLLMHandler(client,
		"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("challenger-001", agentbus.NewLLMHandler(client,
		"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("reviewer-001", agentbus.NewLLMHandler(client,
		"You are the Reviewer Agent in TEECheck. Another agent asks you about your verification. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))

	return bus
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
