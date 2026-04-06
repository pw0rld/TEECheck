package collabrun

import (
	"fmt"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
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
	if err := expert.Run(stageCfg); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	stageCfg.AgentID = "challenger-001"
	if err := challenger.Run(stageCfg); err != nil {
		return "", fmt.Errorf("challenger: %w", err)
	}

	stageCfg.AgentID = "verifier-001"
	if err := verifier.Run(stageCfg); err != nil {
		return "", fmt.Errorf("verifier: %w", err)
	}

	stageCfg.AgentID = "arbiter-001"
	if err := arbiter.Run(stageCfg); err != nil {
		return "", fmt.Errorf("arbiter: %w", err)
	}

	return runDir, nil
}
