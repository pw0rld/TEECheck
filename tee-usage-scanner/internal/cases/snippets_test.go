package cases

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return rel
}

func TestCollectSnippets_SmallFileIncludesEverything(t *testing.T) {
	dir := t.TempDir()
	rel := writeTestFile(t, dir, "src/foo.rs", strings.Repeat("// short file line\n", 50))

	snips := collectSnippets(dir, []string{rel}, nil)
	if len(snips) != 1 {
		t.Fatalf("want 1 snippet, got %d", len(snips))
	}
	if snips[0].StartLine != 1 {
		t.Errorf("StartLine = %d, want 1", snips[0].StartLine)
	}
	if snips[0].EndLine != 50 {
		t.Errorf("EndLine = %d, want 50 (small file should include all)", snips[0].EndLine)
	}
	// Should contain a line from the middle of the file.
	if !strings.Contains(snips[0].Content, "// short file line") {
		t.Errorf("content missing expected line")
	}
}

func TestCollectSnippets_LargeFileWithSymbolReturnsWindowAroundSymbol(t *testing.T) {
	dir := t.TempDir()
	// 1000 lines of filler with verify_quote on line 500.
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		if i == 500 {
			b.WriteString("pub fn verify_quote(quote: &[u8]) -> Result<()> {\n")
		} else {
			b.WriteString("// filler line " + strings.Repeat("x", 5) + "\n")
		}
	}
	rel := writeTestFile(t, dir, "src/big.rs", b.String())

	snips := collectSnippets(dir, []string{rel}, []string{"verify_quote"})
	if len(snips) == 0 {
		t.Fatal("expected at least 1 snippet")
	}
	// Find the snippet that contains verify_quote.
	var hit *struct {
		start, end int
		content    string
	}
	for _, s := range snips {
		if strings.Contains(s.Content, "verify_quote") {
			hit = &struct {
				start, end int
				content    string
			}{s.StartLine, s.EndLine, s.Content}
			break
		}
	}
	if hit == nil {
		t.Fatalf("no snippet contained verify_quote; got %d snippets", len(snips))
	}
	// The window should be roughly centered on line 500 (±50ish).
	if hit.start > 500 || hit.end < 500 {
		t.Errorf("window [%d, %d] does not cover line 500", hit.start, hit.end)
	}
	if hit.start < 440 || hit.end > 560 {
		t.Errorf("window [%d, %d] is too wide; want roughly ±50 around line 500", hit.start, hit.end)
	}
}

func TestCollectSnippets_LargeFileWithoutSymbolMatchFallsBackToHead(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 1; i <= 800; i++ {
		b.WriteString("// nothing interesting here\n")
	}
	rel := writeTestFile(t, dir, "src/dull.rs", b.String())

	snips := collectSnippets(dir, []string{rel}, []string{"nonexistent_symbol"})
	if len(snips) != 1 {
		t.Fatalf("want 1 snippet, got %d", len(snips))
	}
	// Fallback should give us at least 50 lines so reviewers see context.
	if snips[0].EndLine < 50 {
		t.Errorf("fallback snippet too small: end=%d", snips[0].EndLine)
	}
}

func TestCollectSnippets_MultipleSymbolsMergeOverlappingWindows(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		switch i {
		case 500:
			b.WriteString("pub fn alpha() {}\n")
		case 530:
			// within ±50 of alpha, so windows overlap
			b.WriteString("pub fn beta() {}\n")
		case 800:
			// far from alpha/beta — separate window
			b.WriteString("pub fn gamma() {}\n")
		default:
			b.WriteString("// filler\n")
		}
	}
	rel := writeTestFile(t, dir, "src/multi.rs", b.String())

	snips := collectSnippets(dir, []string{rel}, []string{"alpha", "beta", "gamma"})
	// Expect 2 snippets (alpha+beta merged into one window, gamma separate).
	if len(snips) != 2 {
		t.Fatalf("want 2 merged snippets, got %d", len(snips))
	}
	// The first should cover both alpha (500) and beta (530).
	first := snips[0]
	if !strings.Contains(first.Content, "alpha") || !strings.Contains(first.Content, "beta") {
		t.Errorf("first snippet should contain both alpha and beta, got: %s", first.Content[:200])
	}
	// The second should cover gamma (800) but not the others.
	second := snips[1]
	if !strings.Contains(second.Content, "gamma") {
		t.Errorf("second snippet should contain gamma")
	}
	if strings.Contains(second.Content, "alpha") {
		t.Errorf("second snippet should NOT contain alpha")
	}
}

func TestCollectSnippets_MissingFileSilentlySkips(t *testing.T) {
	dir := t.TempDir()
	snips := collectSnippets(dir, []string{"does/not/exist.rs"}, []string{"foo"})
	if len(snips) != 0 {
		t.Fatalf("missing file should produce 0 snippets, got %d", len(snips))
	}
}

func TestCollectSnippets_DedupesPaths(t *testing.T) {
	dir := t.TempDir()
	rel := writeTestFile(t, dir, "src/foo.rs", "fn x() {}\n")
	snips := collectSnippets(dir, []string{rel, rel, rel}, nil)
	if len(snips) != 1 {
		t.Fatalf("dup paths should dedupe to 1 snippet, got %d", len(snips))
	}
}
