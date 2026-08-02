package pipeline

import (
	"strings"
	"testing"
)

// The whole point of the event is that the run can be re-issued from it, so
// every argument the user typed has to survive verbatim.
func TestLaunchCommand_KeepsEveryArgument(t *testing.T) {
	got := launchCommand([]string{
		"teecheck", "run", "https://github.com/OP-TEE/optee_os",
		"--commit", "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e",
		"--run-id", "run-c", "--hint", "I suspect the TA loading path",
	})
	want := "teecheck run https://github.com/OP-TEE/optee_os " +
		"--commit a9386bf987d95374a6f7f4c7bcf850115e0e1a4e " +
		"--run-id run-c --hint I suspect the TA loading path"
	if got != want {
		t.Errorf("launchCommand()\n got: %s\nwant: %s", got, want)
	}
}

// events.jsonl travels with bug reports and benchmark results. A key that
// reaches it is a leaked key.
func TestLaunchCommand_RedactsAPIKey(t *testing.T) {
	const secret = "example-api-key-not-a-real-credential"
	for _, argv := range [][]string{
		{"teecheck", "run", ".", "--llm-api-key", secret, "--focus", "tee"},
		{"teecheck", "run", ".", "--llm-api-key=" + secret},
		{"teecheck", "run", ".", "-llm-api-key", secret},
	} {
		got := launchCommand(argv)
		if strings.Contains(got, secret) {
			t.Errorf("launchCommand(%v) leaked the key: %s", argv, got)
		}
		if !strings.Contains(got, redacted) {
			t.Errorf("launchCommand(%v) dropped the key without saying so: %s", argv, got)
		}
		if !strings.Contains(got, "llm-api-key") {
			t.Errorf("launchCommand(%v) lost the flag name: %s", argv, got)
		}
	}
}

// A trailing --llm-api-key has no value to redact. Appending a placeholder
// would put an argument in the record that was never on the command line.
func TestLaunchCommand_TrailingFlagInventsNothing(t *testing.T) {
	got := launchCommand([]string{"teecheck", "run", ".", "--llm-api-key"})
	if want := "teecheck run . --llm-api-key"; got != want {
		t.Errorf("launchCommand() = %q, want %q", got, want)
	}
}

// The redaction must key on the flag, not on the shape of the value: a
// commit SHA and an API key are both long opaque strings.
func TestLaunchCommand_RedactsOnlyTheKeyFlag(t *testing.T) {
	got := launchCommand([]string{
		"teecheck", "run", ".", "--commit", "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e",
	})
	if !strings.Contains(got, "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e") {
		t.Errorf("launchCommand() redacted the commit: %s", got)
	}
}
