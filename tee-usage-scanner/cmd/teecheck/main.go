package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/collabrun"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/hotspots"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomap"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch cfg.Command {
	case "knowledge-init":
		err = knowledge.RunInit(cfg)
	case "collab-run":
		var runPath string
		runPath, err = collabrun.Run(cfg, time.Now())
		if err == nil {
			fmt.Printf("Collaborative run completed at %s\n", runPath)
		}
	case "init-run":
		var runPath string
		runPath, err = runinit.Run(cfg, time.Now())
		if err == nil {
			fmt.Printf("Run initialized at %s\n", runPath)
		}
	case "preprocess":
		err = preprocessor.Run(cfg)
	case "mapper":
		err = mapper.Run(cfg)
	case "map":
		err = repomap.Run(cfg)
	case "hotspots":
		err = hotspots.Run(cfg)
	case "cases":
		err = cases.Run(cfg)
	case "expert":
		err = expert.Run(cfg)
	case "challenge":
		err = challenger.Run(cfg)
	case "verifier":
		err = verifier.Run(cfg)
	case "arbiter":
		err = arbiter.Run(cfg)
	case "review":
		err = review.Run(cfg)
	case "feedback":
		err = feedback.Run(cfg, os.Stdout)
	case "curator":
		if strings.EqualFold(cfg.CuratorMode, "llm") {
			bus := buildCuratorBus(cfg)
			err = feedback.RunWithBus(cfg, os.Stdout, bus)
		} else {
			err = feedback.Run(cfg, os.Stdout)
		}
	case "run":
		var runPath string
		runPath, err = pipeline.Run(cfg)
		if err == nil {
			fmt.Printf("\nPipeline completed. Results at %s\n", runPath)
		}
	case "plan":
		err = runPlanCommand(cfg)
	default:
		err = fmt.Errorf("unsupported command: %s", cfg.Command)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildCuratorBus(cfg config.Config) *agentbus.Bus {
	client := llm.NewClient(cfg)
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
