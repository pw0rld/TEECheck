package collabrun

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func Run(cfg config.Config, now time.Time) (string, error) {
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return "", fmt.Errorf("ensure knowledge layout: %w", err)
	}
	initCfg := cfg
	initCfg.Command = "init-run"
	runDir, err := runinit.Run(initCfg, now)
	if err != nil {
		return "", err
	}

	stageCfg := cfg
	stageCfg.RunDir = runDir

	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}
	if err := mapper.Run(stageCfg); err != nil {
		return "", fmt.Errorf("mapper: %w", err)
	}
	if err := cases.Run(stageCfg); err != nil {
		return "", fmt.Errorf("cases: %w", err)
	}

	stageCfg.AgentID = "expert-001"
	client := llm.NewClient(stageCfg)
	if err := expert.Run(stageCfg, client); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	stageCfg.AgentID = "challenger-001"
	if err := challenger.Run(stageCfg, client); err != nil {
		return "", fmt.Errorf("challenger: %w", err)
	}

	needsBus := anyLLMMode(cfg.VerifierMode, cfg.ArbiterMode)

	if needsBus {
		bus := buildBus(cfg)

		stageCfg.AgentID = "verifier-001"
		if strings.EqualFold(cfg.VerifierMode, "llm") {
			if err := verifier.RunWithBus(stageCfg, bus); err != nil {
				return "", fmt.Errorf("verifier: %w", err)
			}
		} else {
			if err := verifier.Run(stageCfg); err != nil {
				return "", fmt.Errorf("verifier: %w", err)
			}
		}

		stageCfg.AgentID = "arbiter-001"
		if strings.EqualFold(cfg.ArbiterMode, "llm") {
			if err := arbiter.RunWithBus(stageCfg, bus); err != nil {
				return "", fmt.Errorf("arbiter: %w", err)
			}
		} else {
			if err := arbiter.Run(stageCfg); err != nil {
				return "", fmt.Errorf("arbiter: %w", err)
			}
		}
	} else {
		stageCfg.AgentID = "verifier-001"
		if err := verifier.Run(stageCfg); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		stageCfg.AgentID = "arbiter-001"
		if err := arbiter.Run(stageCfg); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	}

	return runDir, nil
}

func anyLLMMode(modes ...string) bool {
	for _, m := range modes {
		if strings.EqualFold(m, "llm") {
			return true
		}
	}
	return false
}

func buildBus(cfg config.Config) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)

	var client llm.Client
	if anyLLMMode(cfg.VerifierMode, cfg.ArbiterMode, cfg.CuratorMode) {
		client = llm.NewClient(cfg)
	}

	if client != nil {
		bus.Register("expert-001", agentbus.NewLLMHandler(client,
			"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
		bus.Register("challenger-001", agentbus.NewLLMHandler(client,
			"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
		bus.Register("verifier-001", agentbus.NewLLMHandler(client,
			"You are the Verifier Agent in TEECheck. Another agent asks you about your verification. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
	}

	reg := scall.NewDefaultRegistry()
	bus.Register("mapper", agentbus.NewToolHandler("mapper", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
		req := staticcheck.CheckRequest{
			RepoRoot: cfg.LocalPath,
			Keywords: strings.Fields(q.Question),
		}
		findings, err := reg.RunAll(ctx, req)
		if err != nil {
			return agentbus.Response{}, err
		}
		var facts []string
		for _, f := range findings {
			facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
		}
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "mapper",
			Answer:    fmt.Sprintf("Found %d results", len(findings)),
			Facts:     facts,
		}, nil
	}))

	return bus
}
