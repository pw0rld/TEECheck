package pipeline

import (
	"reflect"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestResumeSettingsIncludeRoleStreaming(t *testing.T) {
	cfg := config.Config{KnowledgeRoot: t.TempDir()}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	before, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	planner := roles["planner"]
	planner.LLMStream = true
	roles["planner"] = planner
	after, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, after) || !after.Roles["planner"].Stream {
		t.Fatal("resume settings ignored streaming change")
	}
}
