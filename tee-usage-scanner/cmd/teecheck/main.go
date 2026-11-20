package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/report"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/reverify"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runvalidate"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func main() {
	// `stats` is handled directly here without going through the
	// config parser — it only needs a run dir and an optional repo
	// root, so we keep the parser surface narrow.
	if len(os.Args) >= 2 && os.Args[1] == "stats" {
		if err := runStats(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch cfg.Command {
	case "knowledge-init":
		err = knowledge.RunInit(cfg)
	case "init-run":
		var runPath string
		runPath, err = runinit.Run(cfg, time.Now())
		if err == nil {
			fmt.Printf("Run initialized at %s\n", runPath)
		}
	case "preprocess":
		err = preprocessor.Run(cfg)
	case "cases":
		err = cases.Run(cfg)
	case "expert":
		client := llm.NewClient(cfg)
		err = expert.Run(cfg, client)
	case "challenge":
		client := llm.NewClient(cfg)
		err = challenger.Run(cfg, client)
	case "verifier":
		client := llm.NewClient(cfg)
		bus := buildStandaloneBus(cfg, client)
		err = verifier.RunWithBus(cfg, client, bus)
	case "arbiter":
		client := llm.NewClient(cfg)
		bus := buildStandaloneBus(cfg, client)
		err = arbiter.RunWithBus(cfg, client, bus)
	case "review":
		err = review.Run(cfg)
	case "feedback", "curator":
		client := llm.NewClient(cfg)
		bus := buildCuratorBus(cfg, client)
		err = feedback.RunWithBus(cfg, client, os.Stdout, bus)
	case "report":
		var client llm.Client
		if cfg.LLMBaseURL != "" && cfg.LLMAPIKey != "" && cfg.LLMModel != "" {
			client = llm.NewClient(cfg)
		}
		err = report.Run(cfg, client)
	case "verify-contract":
		var output string
		output, err = reverify.Run(cfg)
		if err == nil {
			fmt.Printf("Contract recheck written to %s\n", output)
		}
	case "validate-run":
		validation := runvalidate.Validate(cfg.RunDir)
		var data []byte
		data, err = json.MarshalIndent(validation, "", "  ")
		if err == nil {
			fmt.Println(string(data))
			if !validation.Valid {
				err = fmt.Errorf("run validation failed with %d issue(s)", len(validation.Issues))
			}
		}
	case "run", "plan":
		// Both spellings use the same LLM-backed pipeline and controls.
		var runPath string
		runPath, err = pipeline.Run(cfg)
		if err == nil {
			fmt.Printf("\nPipeline completed. Results at %s\n", runPath)
		}
	default:
		err = fmt.Errorf("unsupported command: %s", cfg.Command)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// buildStandaloneBus builds a bus for the standalone verifier/arbiter
// subcommands. Mirrors the one in internal/pipeline/run.go but lives
// here so the subcommand dispatch in this file can stay self-contained.
func buildStandaloneBus(cfg config.Config, client llm.Client) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)
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

func buildCuratorBus(cfg config.Config, client llm.Client) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)
	bus.Register("expert-001", agentbus.NewLLMHandler(client,
		"You are the Expert Agent. Another agent asks about your analysis. Return JSON with: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("arbiter-001", agentbus.NewLLMHandler(client,
		"You are the Arbiter Agent. Another agent asks about your judgment. Return JSON with: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	return bus
}
