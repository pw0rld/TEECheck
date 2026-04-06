package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/collabrun"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/hotspots"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
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
	default:
		err = fmt.Errorf("unsupported command: %s", cfg.Command)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
