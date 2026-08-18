package repomix_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomix"
)

func TestPackAndFormat(t *testing.T) {
	eventstest.FakeBinary(t, "npx", `
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then OUT="$a"; fi
  prev="$a"
done
cat > "$OUT" <<'BODY'
{"directoryStructure":"main.rs\n","files":{"main.rs":"pub fn verify_quote() {}\n"}}
BODY
`)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.rs"), []byte(`
pub fn verify_quote(report: &Report) -> Result<(), Error> {
    check_freshness(report)?;
    check_signature(report)?;
    Ok(())
}

fn check_freshness(report: &Report) -> Result<(), Error> {
    if report.timestamp < MIN_TIMESTAMP {
        return Err(Error::StaleQuote);
    }
    Ok(())
}

fn check_signature(report: &Report) -> Result<(), Error> {
    // TODO: implement full signature verification
    Ok(())
}

pub struct Report {
    pub timestamp: u64,
    pub signature: Vec<u8>,
}
`), 0o644)

	result, err := repomix.Pack(context.Background(), repomix.PackRequest{
		RepoRoot:    dir,
		TargetFiles: []string{"main.rs"},
		Compress:    true,
	})
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	if len(result.Files) == 0 {
		t.Fatal("expected at least one file in result")
	}

	for path, content := range result.Files {
		t.Logf("File: %s, content length: %d", path, len(content))
		if content == "" {
			t.Fatalf("empty content for %s", path)
		}
	}

	formatted := repomix.FormatForPrompt(result, 4000)
	if formatted == "" {
		t.Fatal("expected non-empty formatted output")
	}
	t.Logf("Formatted output (%d chars):\n%s", len(formatted), formatted[:min(len(formatted), 500)])
}

func TestAvailable(t *testing.T) {
	// Just verify it doesn't panic
	_ = repomix.Available()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
