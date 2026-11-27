package pipeline

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// RoleClients are selected before the run starts. Default provides backwards
// compatible injection; no response, refusal or error changes this routing.
// Optional legacy-prior stages use the planner's client and configuration.
type RoleClients struct {
	Default    llm.Client
	Planner    llm.Client
	Scout      llm.Client
	Expert     llm.Client
	Challenger llm.Client
	Verifier   llm.Client
	Arbiter    llm.Client
}

func (clients RoleClients) forRole(role string) llm.Client {
	var client llm.Client
	switch role {
	case "scout":
		client = clients.Scout
		if client == nil {
			client = clients.Planner
		}
	case "expert":
		client = clients.Expert
	case "challenger":
		client = clients.Challenger
	case "verifier":
		client = clients.Verifier
	case "arbiter":
		client = clients.Arbiter
	default:
		client = clients.Planner
	}
	if client == nil {
		return clients.Default
	}
	return client
}

func agentRole(agentID string) string {
	role := strings.TrimSuffix(agentID, "-001")
	switch role {
	case "expert", "challenger", "verifier", "arbiter":
		return role
	case "reviewer":
		return "verifier"
	default:
		return "planner"
	}
}

func RunWithClient(cfg config.Config, client llm.Client) (string, error) {
	return RunWithClients(cfg, RoleClients{Default: client})
}

func RunWithClients(cfg config.Config, clients RoleClients) (string, error) {
	settings, err := cfg.ResolveRoleConfigs()
	if err != nil {
		return "", err
	}
	for _, role := range config.LLMRoles {
		if clients.forRole(role) == nil {
			return "", fmt.Errorf("missing client for %s role", role)
		}
	}
	return runWithRoleClients(cfg, clients, settings)
}

func withRoleSettings(base, role config.Config) config.Config {
	return base.WithLLMSettingsFrom(role)
}
