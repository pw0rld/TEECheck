package config

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestParseValidateRun(t *testing.T) {
	cfg, err := Parse([]string{"validate-run", "--run-dir", "/tmp/run-1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Command != "validate-run" || cfg.RunDir != "/tmp/run-1" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if _, err := Parse([]string{"validate-run"}); err == nil {
		t.Fatal("Parse accepted validate-run without --run-dir")
	}
}

func TestParseRun_ResolvesTransportAndReasoningEffort(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "gpt-5.6-terra")
	t.Setenv("TEECHECK_LLM_TRANSPORT", "responses")
	t.Setenv("TEECHECK_LLM_REASONING_EFFORT", "high")

	cfg, err := Parse([]string{"run", "."})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LLMTransport != "responses" || cfg.LLMReasoningEffort != "high" {
		t.Fatalf("transport=%q reasoning_effort=%q", cfg.LLMTransport, cfg.LLMReasoningEffort)
	}
}

func TestParseRun_RejectsUnknownResponsesControls(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "transport", args: []string{"--llm-transport", "completionz"}},
		{name: "reasoning effort", args: []string{"--llm-transport", "responses", "--llm-reasoning-effort", "extreme"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
			t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
			t.Setenv("TEECHECK_LLM_MODEL", "gpt-5.6-terra")
			args := append([]string{"run", "."}, tc.args...)
			if _, err := Parse(args); err == nil {
				t.Fatalf("Parse accepted invalid controls: %v", tc.args)
			}
		})
	}
}

// ─── The API key must never reach the usage output ───────────────────

// On 2026-07-28 a live API key was printed to a terminal and into a task log
// by a single mistyped flag: --llm-api-key was bound with StringVar whose
// default was the environment's value, and the flag package echoes defaults in
// every usage dump — on a parse error, not only on --help.
//
// The property that prevents it is that the flag's registered DefValue is
// empty no matter what the environment holds.
func TestLLMAPIKeyFlagHasNoDefaultToLeak(t *testing.T) {
	const secret = "sk-live-do-not-print-me"

	var out bytes.Buffer
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(&out)
	key := secret // stands in for cfg.LLMAPIKey, pre-filled from the environment
	fs.Var(redactedKey{&key}, "llm-api-key", "LLM API key")
	fs.PrintDefaults()

	if strings.Contains(out.String(), secret) {
		t.Fatalf("the API key reached the usage output:\n%s", out.String())
	}
	if got := fs.Lookup("llm-api-key").DefValue; got != "" {
		t.Fatalf("DefValue = %q, want empty — a non-empty default is printed verbatim", got)
	}
	// Redacting the default must not cost the program access to the value.
	if key != secret {
		t.Fatalf("binding clobbered the value it was given: %q", key)
	}
}

// The flag must still be settable, and setting it must reach the target.
func TestRedactedKey_SetReachesTarget(t *testing.T) {
	var got string
	if err := (redactedKey{&got}).Set("sk-explicit"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got != "sk-explicit" {
		t.Fatalf("Set stored %q", got)
	}
	// A nil target must not panic — the flag package constructs a zero value
	// of the type when deciding whether a default is the zero value.
	if s := (redactedKey{}).String(); s != "" {
		t.Fatalf("zero-value String() = %q, want empty", s)
	}
	if err := (redactedKey{}).Set("x"); err != nil {
		t.Fatalf("Set on a nil target must not error: %v", err)
	}
}

// ─── Environment fallback survives the redaction ─────────────────────

func TestParse_APIKeyStillComesFromEnvironment(t *testing.T) {
	const secret = "sk-from-environment"
	t.Setenv("TEECHECK_LLM_API_KEY", secret)
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")

	cfg, err := Parse([]string{"run", "."})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.LLMAPIKey != secret {
		t.Fatalf("LLMAPIKey = %q, want the environment's value", cfg.LLMAPIKey)
	}
}

func TestParse_ExplicitAPIKeyFlagWins(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "sk-from-environment")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")

	cfg, err := Parse([]string{"run", ".", "--llm-api-key", "sk-explicit"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.LLMAPIKey != "sk-explicit" {
		t.Fatalf("LLMAPIKey = %q, want the flag's value", cfg.LLMAPIKey)
	}
}

// ─── Default LLM timeout ─────────────────────────────────────────────

// The 60s default silently broke every reasoning model: glm-5.2 spends most of
// its budget on reasoning tokens, and the architecture stage — the first LLM
// call of a run — exhausted three retries and aborted before emitting anything.
func TestParse_DefaultLLMTimeoutFitsReasoningModels(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "k")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")

	cfg, err := Parse([]string{"run", "."})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.LLMTimeoutSec < 300 {
		t.Fatalf("default LLM timeout = %ds, want >= 300s", cfg.LLMTimeoutSec)
	}
}

// The dialog budget has an empirical floor. At 3 — and shared across every
// stage before the quota became per-asking-agent — run 44362-vuln-p8's
// arbiter reported "dialog round limit (3) reached" and closed the finding
// with the rollback question unasked, because the verifier had already spent
// the budget once scanner-001 started answering. Lowering this silently
// re-creates that.
func TestParse_DialogBudgetIsNotBackAtThree(t *testing.T) {
	if DefaultMaxDialogRounds < 10 {
		t.Fatalf("DefaultMaxDialogRounds = %d; 3 was measured to starve the arbiter of "+
			"its follow-up questions once the tool-backed agent worked", DefaultMaxDialogRounds)
	}
	cfg, err := Parse([]string{"run", "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxDialogRounds != DefaultMaxDialogRounds {
		t.Fatalf("cfg.MaxDialogRounds = %d, want the package default %d",
			cfg.MaxDialogRounds, DefaultMaxDialogRounds)
	}
}
