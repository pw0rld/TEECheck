package pipeline

import (
	"reflect"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestResumeSettingsIncludeShardedRoutingAndFormalVerification(t *testing.T) {
	base := config.Config{KnowledgeRoot: t.TempDir(), PlannerWorkers: 4, LLMModel: "planner-model"}
	roles, err := base.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	original, err := resolvedResumeSettings(base, roles)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config, map[string]config.Config)
	}{
		{"workers", func(c *config.Config, _ map[string]config.Config) { c.PlannerWorkers = 1 }},
		{"planner mode", func(c *config.Config, _ map[string]config.Config) { c.UseMonolithicPlanner = true }},
		{"formal verification", func(c *config.Config, _ map[string]config.Config) { c.EnableFormalVerify = true }},
		{"scout route", func(_ *config.Config, r map[string]config.Config) {
			scout := r["scout"]
			scout.LLMModel = "different-scout-model"
			r["scout"] = scout
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			changedRoles := make(map[string]config.Config, len(roles))
			for role, settings := range roles {
				changedRoles[role] = settings
			}
			tc.mutate(&changed, changedRoles)
			current, err := resolvedResumeSettings(changed, changedRoles)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(current, original) {
				t.Fatal("changed execution settings would silently resume the original run")
			}
		})
	}
}
