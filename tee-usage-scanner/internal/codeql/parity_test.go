package codeql

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// codeql is not installed in this repo's dev/CI image. Every test here
// points Engine at a stand-in script via NewWithBin — which is the real
// production path for a bundle install, so nothing about the call is
// special-cased for testing. The subprocess is real; only the program is a
// fake. That proves the WIRING and the RECORD, not real CodeQL behaviour.

// fakeCodeQL writes a script that dumps its argv (one per line) to
// $ARGV_OUT, echoes onOut to stdout and onErr to stderr, optionally writes
// sarif into the file named by the --output= argument, then exits code.
func fakeCodeQL(t *testing.T, onOut, onErr, sarif string, code int) (bin, argvFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "codeql")
	argvFile = filepath.Join(dir, "argv")
	t.Setenv("ARGV_OUT", argvFile)

	script := `#!/bin/sh
for a in "$@"; do
  echo "$a" >> "$ARGV_OUT"
  case "$a" in --output=*) OUT="${a#--output=}" ;; esac
done
[ -n "` + onOut + `" ] && printf '%s\n' '` + onOut + `'
[ -n "` + onErr + `" ] && printf '%s\n' '` + onErr + `' >&2
`
	if sarif != "" {
		script += `[ -n "$OUT" ] && cat > "$OUT" <<'SARIF'
` + sarif + `
SARIF
`
	}
	script += "exit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argvFile
}

const emptySARIF = `{"runs":[{"results":[]}]}`

func readArgv(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read argv dump: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func equalArgs(a, b []string) bool {
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

// ─── behaviour parity ────────────────────────────────────────────────
//
// Written and run green against the pre-executor implementation, then
// re-run unchanged afterwards. What they pin — argv, the error-string
// shape including the trailing output tail, and the ExtraPATH contract —
// is what routing through the executor was not allowed to change.

func TestParity_CreateDatabaseArgv(t *testing.T) {
	bin, argvFile := fakeCodeQL(t, "", "", "", 0)
	e := NewWithBin(bin)

	if err := e.CreateDatabase(context.Background(), CreateDBOptions{
		Language:   "cpp",
		SourceRoot: "/src/tree",
		DBPath:     "/out/db",
		Overwrite:  true,
		BuildMode:  "none",
	}); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}

	want := []string{
		"database", "create", "/out/db",
		"--language=cpp", "--source-root=/src/tree",
		"--overwrite", "--build-mode=none",
	}
	if got := readArgv(t, argvFile); !equalArgs(got, want) {
		t.Errorf("argv =\n  %q\nwant\n  %q", got, want)
	}
}

func TestParity_AnalyzeArgv(t *testing.T) {
	bin, argvFile := fakeCodeQL(t, "", "", emptySARIF, 0)
	e := NewWithBin(bin)

	if _, err := e.Analyze(context.Background(), AnalyzeOptions{
		DBPath:          "/out/db",
		Queries:         []string{"a.ql", "b.ql"},
		AdditionalPacks: []string{"/packs/one", "/packs/two"},
	}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	got := readArgv(t, argvFile)
	// --output= names a temp file whose path is not predictable; everything
	// else, including ordering, is pinned exactly.
	if len(got) < 5 || !strings.HasPrefix(got[4], "--output=") || !strings.Contains(got[4], "teecheck-") {
		t.Fatalf("argv = %q, want a --output=<temp sarif> at index 4", got)
	}
	got[4] = "--output=<temp>"
	want := []string{
		"database", "analyze", "/out/db",
		"--format=sarifv2.1.0", "--output=<temp>", "--rerun",
		"--additional-packs=/packs/one" + string(os.PathListSeparator) + "/packs/two",
		"a.ql", "b.ql",
	}
	if !equalArgs(got, want) {
		t.Errorf("argv =\n  %q\nwant\n  %q", got, want)
	}
}

// The error string is the diagnostic someone reads when CodeQL dies. It
// must keep both halves: the wrapped exec error, and the tail of what the
// process printed.
func TestParity_CreateDatabaseFailureErrorString(t *testing.T) {
	bin, _ := fakeCodeQL(t, "progress line", "fatal: extractor exploded", "", 32)
	err := NewWithBin(bin).CreateDatabase(context.Background(), CreateDBOptions{
		Language: "cpp", SourceRoot: "/s", DBPath: "/d",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "codeql database create failed: exit status 32\n") {
		t.Errorf("err = %q, want prefix %q", msg, "codeql database create failed: exit status 32\\n")
	}
	if !strings.Contains(msg, "fatal: extractor exploded") {
		t.Errorf("err = %q, must carry the process's own diagnostic", msg)
	}
}

func TestParity_AnalyzeFailureErrorString(t *testing.T) {
	bin, _ := fakeCodeQL(t, "", "fatal: query did not compile", "", 2)
	_, err := NewWithBin(bin).Analyze(context.Background(), AnalyzeOptions{
		DBPath: "/d", Queries: []string{"q.ql"},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "codeql database analyze failed: exit status 2\n") {
		t.Errorf("err = %q", msg)
	}
	if !strings.Contains(msg, "fatal: query did not compile") {
		t.Errorf("err = %q, must carry the process's own diagnostic", msg)
	}
}

// ExtraPATH is prepended to PATH for the child. The Rust extractor needs
// this to find cargo, so it is load-bearing, not decorative.
func TestParity_ExtraPATHReachesTheChild(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codeql")
	out := filepath.Join(dir, "path-seen")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' \"$PATH\" > "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := NewWithBin(bin).CreateDatabase(context.Background(), CreateDBOptions{
		Language: "cpp", SourceRoot: "/s", DBPath: "/d", ExtraPATH: "/opt/cargo/bin",
	}); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	seen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(seen), "/opt/cargo/bin"+string(os.PathListSeparator)) {
		t.Errorf("child PATH = %q, want it to start with the ExtraPATH entry", seen)
	}
}

// The child inherits the parent environment. CodeQL reads a great deal
// from the environment (LANG, TMPDIR, proxy settings, its own CODEQL_*
// knobs); an executor that passed only PATH+HOME would break it in ways
// no unit test of ours would catch, so the inheritance is pinned here.
func TestParity_ChildInheritsParentEnvironment(t *testing.T) {
	t.Setenv("TEECHECK_PARITY_CANARY", "canary-value")
	dir := t.TempDir()
	bin := filepath.Join(dir, "codeql")
	out := filepath.Join(dir, "env-seen")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' \"$TEECHECK_PARITY_CANARY\" > "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := NewWithBin(bin).CreateDatabase(context.Background(), CreateDBOptions{
		Language: "cpp", SourceRoot: "/s", DBPath: "/d",
	}); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	seen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(seen) != "canary-value" {
		t.Errorf("child saw TEECHECK_PARITY_CANARY=%q, want %q", seen, "canary-value")
	}
}
