package llm

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"

func NewClient(cfg config.Config) Client {
	return NewOpenAIClient(cfg)
}
