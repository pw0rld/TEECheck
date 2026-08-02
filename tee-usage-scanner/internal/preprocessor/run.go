package preprocessor

import (
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config) error {
	if _, err := runfs.LoadManifest(cfg.RunDir); err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	tweContextWritten, err := compileTWEKnowledge(cfg.KnowledgeRoot, cfg.RunDir)
	if err != nil {
		return fmt.Errorf("compile TWE prior knowledge: %w", err)
	}
	if tweContextWritten {
		fmt.Printf("TWE agent context written to %s\n", runfs.TWEAgentContextPath(cfg.RunDir))
	}
	return nil
}
