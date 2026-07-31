package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// semgrep is not installed in this repo's dev/CI image, so every test here
// puts a stand-in on PATH. The subprocess is real — a real fork/exec, real
// argv, real exit code, real stdout/stderr — only the program is a fake.
// That proves the WIRING and the RECORD; it proves nothing about how real
// semgrep behaves, which is stated plainly in the report.

const sampleJSON = `{"results":[{"check_id":"r.one","path":"src/a.rs",` +
	`"start":{"line":7,"col":1},"end":{"line":9,"col":2},` +
	`"extra":{"message":"boom","severity":"ERROR","lines":"let x = 1;"}}]}`

// fakeSemgrep installs a "semgrep" on PATH that dumps its argv (one per
// line) to $ARGV_OUT, prints body, and exits with code.
func fakeSemgrep(t *testing.T, body string, code int) (argvFile string) {
	t.Helper()
	argvFile = filepath.Join(t.TempDir(), "argv")
	t.Setenv("ARGV_OUT", argvFile)
	eventstest.FakeBinary(t, "semgrep", `
for a in "$@"; do echo "$a" >> "$ARGV_OUT"; done
cat <<'BODY'
`+body+`
BODY
exit `+itoa(code)+`
`)
	return argvFile
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func readArgv(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read argv dump: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// ─── behaviour parity ────────────────────────────────────────────────
//
// These four tests are the parity harness. They were written and run
// against the pre-executor implementation, where they passed; they are
// re-run unchanged afterwards. Anything they pin — argv, working
// directory, which exit codes are treated as tool output rather than
// execution failure, and the error strings — is behaviour that routing
// through the executor was not allowed to change.

func TestParity_ArgvAndSuccessfulParse(t *testing.T) {
	argvFile := fakeSemgrep(t, sampleJSON, 0)
	a := New()

	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    "/repo/root",
		TargetFiles: []string{"src/a.rs", "src/b.rs"},
		ExtraArgs:   map[string]string{"config": "p/security"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "r.one" || findings[0].StartLine != 7 {
		t.Fatalf("findings = %+v", findings)
	}

	want := []string{
		"--json", "--no-git-ignore", "--config=p/security",
		"--include=src/a.rs", "--include=src/b.rs", "/repo/root",
	}
	if got := readArgv(t, argvFile); !equal(got, want) {
		t.Errorf("argv =\n  %q\nwant\n  %q", got, want)
	}
}

// A non-zero exit with usable JSON on stdout is a NORMAL semgrep outcome
// (it exits non-zero when it found something). It must be parsed, not
// treated as an execution failure — this is the exact distinction the
// executor's Error-vs-ExitCode contract exists to preserve.
func TestParity_NonZeroExitWithJSONStillParses(t *testing.T) {
	fakeSemgrep(t, sampleJSON, 1)
	findings, err := New().Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"})
	if err != nil {
		t.Fatalf("non-zero exit with valid JSON must still parse, got: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

// Non-zero exit with nothing on stdout falls back to stderr, which is not
// JSON — so the caller sees a parse error, not an exec error. Pinning the
// prefix pins which of the two error families this case lands in.
func TestParity_NonZeroExitEmptyStdoutFallsBackToStderr(t *testing.T) {
	eventstest.FakeBinary(t, "semgrep", `echo "fatal: bad config" >&2; exit 2`)
	_, err := New().Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "parse semgrep json:") {
		t.Errorf("err = %q, want a parse error (stderr was substituted for empty stdout)", err)
	}
}

func TestParity_MissingBinaryIsAnExecError(t *testing.T) {
	// Empty PATH: nothing resolves.
	t.Setenv("PATH", t.TempDir())
	_, err := New().Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "semgrep exec:") {
		t.Errorf("err = %q, want the \"semgrep exec:\" family", err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
