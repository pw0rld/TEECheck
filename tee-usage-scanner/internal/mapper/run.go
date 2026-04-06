package mapper

import (
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/hotspots"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomap"
)

func Run(cfg config.Config) error {
	if err := repomap.Run(cfg); err != nil {
		return fmt.Errorf("mapper repo_map stage: %w", err)
	}
	if err := hotspots.Run(cfg); err != nil {
		return fmt.Errorf("mapper hotspot stage: %w", err)
	}
	return nil
}
