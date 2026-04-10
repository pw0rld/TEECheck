package knowledge

import (
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func RunInit(cfg config.Config) error {
	if err := EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return err
	}
	fmt.Printf("Knowledge layout ready at %s\n", cfg.KnowledgeRoot)
	return nil
}
