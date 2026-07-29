package repomix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
)

// The `repomix` npm package is not installed in this repo's dev/CI image
// (npx is, but invoking it for real would reach the npm registry). Every
// test here puts a stand-in `npx` on PATH. The subprocess is real; only the
// program is a fake. That proves the WIRING and the RECORD, not real
// repomix behaviour.

const samplePack = `{"directoryStructure":"src/\n  a.rs\n","files":{"src/a.rs":"fn main() {}\n"}}`

// fakeNPX installs an `npx` that dumps argv to $ARGV_OUT, writes body into
// the file named by the argument following "-o", and exits code.
func fakeNPX(t *testing.T, body string, code int) (argvFile string) {
	t.Helper()
	argvFile = filepath.Join(t.TempDir(), "argv")
	t.Setenv("ARGV_OUT", argvFile)
	eventstest.FakeBinary(t, "npx", `
prev=""
for a in "$@"; do
  echo "$a" >> "$ARGV_OUT"
  if [ "$prev" = "-o" ]; then OUT="$a"; fi
  prev="$a"
done
if [ -n "$OUT" ]; then
  cat > "$OUT" <<'BODY'
`+body+`
BODY
fi
exit `+itoaTest(code)+`
`)
	return argvFile
}

func itoaTest(i int) string {
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
// re-run unchanged afterwards.

func TestParity_ArgvAndResultParse(t *testing.T) {
	argvFile := fakeNPX(t, samplePack, 0)

	res, err := Pack(context.Background(), PackRequest{
		RepoRoot:    "/repo/root",
		TargetFiles: []string{"src/a.rs", "src/b.rs"},
		Compress:    true,
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if res.Files["src/a.rs"] != "fn main() {}\n" {
		t.Errorf("files = %#v", res.Files)
	}
	if res.DirectoryStructure == "" {
		t.Error("directory structure was dropped")
	}

	got := readArgv(t, argvFile)
	if len(got) < 2 || got[len(got)-2] != "-o" {
		t.Fatalf("argv = %q, want it to end with -o <temp file>", got)
	}
	outPath := got[len(got)-1]
	if !strings.Contains(outPath, "repomix-") || !strings.HasSuffix(outPath, ".json") {
		t.Errorf("-o target = %q, want a repomix-*.json temp file", outPath)
	}
	got[len(got)-1] = "<temp>"
	want := []string{
		"repomix", "/repo/root", "--style", "json", "--compress",
		"--include", "src/a.rs", "--include", "src/b.rs", "-o", "<temp>",
	}
	if !equalArgs(got, want) {
		t.Errorf("argv =\n  %q\nwant\n  %q", got, want)
	}
}

// The temp output file must not survive the call — Pack owns it.
func TestParity_TempOutputFileIsRemoved(t *testing.T) {
	argvFile := fakeNPX(t, samplePack, 0)
	if _, err := Pack(context.Background(), PackRequest{RepoRoot: "/repo"}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got := readArgv(t, argvFile)
	outPath := got[len(got)-1]
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("temp file %s still exists after Pack returned (stat err = %v)", outPath, err)
	}
}

func TestParity_NonZeroExitIsAnError(t *testing.T) {
	fakeNPX(t, samplePack, 3)
	_, err := Pack(context.Background(), PackRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "repomix: ") {
		t.Errorf("err = %q, want the \"repomix: \" family", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("err = %q, want the exit status preserved", err)
	}
}

func TestParity_MissingBinaryIsAnError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := Pack(context.Background(), PackRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "repomix: ") {
		t.Errorf("err = %q, want the \"repomix: \" family", err)
	}
}

// A successful run whose output file holds unparseable JSON is a parse
// error, distinct from an exec error.
func TestParity_BadJSONIsAParseError(t *testing.T) {
	fakeNPX(t, "not json at all", 0)
	_, err := Pack(context.Background(), PackRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "parse repomix json:") {
		t.Errorf("err = %q, want a parse error", err)
	}
}
