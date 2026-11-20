package runfs

import (
	"os"
	"testing"
)

func TestLegacyPriorPolicyDistinguishesOldAndExplicitlyDisabledRuns(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"old manifest", `{"run_id":"old"}`, true},
		{"old configuration", `{"configuration":{"mode":"llm"}}`, true},
		{"disabled", `{"configuration":{"enable_legacy_prior":false}}`, false},
		{"enabled", `{"configuration":{"enable_legacy_prior":true}}`, true},
		{"invalid policy", `{"configuration":{"enable_legacy_prior":"false"}}`, false},
		{"invalid manifest", `{`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(ManifestPath(dir), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if got := LegacyPriorEnabled(dir); got != tc.want {
				t.Fatalf("enabled=%v, want %v", got, tc.want)
			}
		})
	}
}
