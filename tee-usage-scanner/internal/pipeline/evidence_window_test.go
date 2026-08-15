package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// TestSliceDefinition_ClosesAtTopLevelBrace: a definition slice must run
// from the definition line to the first top-level "}", not the file end —
// and an INDENTED inner brace must not close it.
func TestSliceDefinition_ClosesAtTopLevelBrace(t *testing.T) {
	root := t.TempDir()
	body := "int producer(void)\n{\n\tint a = 1;\n\tif (a) {\n\t\ta++;\n\t}\n\treturn a;\n}\n\nint later(void)\n{\n\treturn 2;\n}\n"
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snip, ok := sliceDefinition(root, "a.c", 1, maxFunctionSnippetLines)
	if !ok {
		t.Fatal("sliceDefinition failed on a readable file")
	}
	if snip.StartLine != 1 || snip.EndLine != 8 {
		t.Errorf("range = %d-%d, want 1-8 (inner \\t} at 6 must NOT close)", snip.StartLine, snip.EndLine)
	}
	if strings.Contains(snip.Content, "later") {
		t.Errorf("slice bled into the next function: %q", snip.Content)
	}
	if strings.Contains(snip.Content, "truncated") {
		t.Errorf("closed slice must not carry a truncation marker: %q", snip.Content)
	}
}

// TestSliceDefinition_StructTerminator (codex-R1 MEDIUM 2): a struct
// definition closes at "};" — the normal C terminator — not at 120 lines.
func TestSliceDefinition_StructTerminator(t *testing.T) {
	root := t.TempDir()
	var sb strings.Builder
	sb.WriteString("#pragma once\n\nstruct shdr_pub_key {\n\tuint32_t version;\n\tuint32_t name_size;\n};\n\nint unrelated(void);\n")
	for i := 0; i < 30; i++ {
		sb.WriteString("/* padding line so the struct is far from EOF */\n")
	}
	if err := os.WriteFile(filepath.Join(root, "signed_hdr.h"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	snip, ok := sliceDefinition(root, "signed_hdr.h", 3, maxStructSnippetLines)
	if !ok {
		t.Fatal("sliceDefinition failed")
	}
	if snip.EndLine != 6 {
		t.Errorf("EndLine = %d, want 6 (close at the }; terminator), content tail: %q", snip.EndLine, snip.Content)
	}
}

// TestSliceDefinition_TrailingCommentClose: "} /* fn */" and "}; /* x */"
// close too; a capped runaway body is marked truncated (codex-R1 LOW 5).
func TestSliceDefinition_TrailingCommentClose(t *testing.T) {
	root := t.TempDir()
	src := "int a(void)\n{\n\treturn 1;\n} /* fn a */\n\nint b(void)\n{\n\treturn 2;\n}; /* never valid but tolerated */\n"
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	snip, _ := sliceDefinition(root, "a.c", 1, maxFunctionSnippetLines)
	if snip.EndLine != 4 {
		t.Errorf("comment-annotated close not recognized: EndLine = %d", snip.EndLine)
	}

	var sb strings.Builder
	sb.WriteString("int f(void)\n{\n")
	for i := 0; i < maxFunctionSnippetLines+50; i++ {
		sb.WriteString("\tline\n")
	}
	if err := os.WriteFile(filepath.Join(root, "b.c"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	snip, ok := sliceDefinition(root, "b.c", 1, maxFunctionSnippetLines)
	if !ok || !strings.Contains(snip.Content, "truncated") {
		t.Errorf("runaway body must be marked truncated, got ok=%v tail=%q", ok, snip.Content)
	}
}

// TestFindStructDefinition_HeaderFallback (codex-R1 BLOCKER): the
// motivating CVE's structs live in a header that is neither a definition
// file nor a target file — the hint-only search could never find them.
// The header walk must locate them.
func TestFindStructDefinition_HeaderFallback(t *testing.T) {
	root := t.TempDir()
	hdr := "#pragma once\n\nstruct shdr_subkey {\n\tuint32_t subkey_version;\n\tuint32_t max_depth;\n};\n\nstruct shdr_pub_key {\n\tuint32_t version;\n\tstruct shdr_subkey *subkey;\n};\n"
	if err := os.MkdirAll(filepath.Join(root, "core/include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "core/include/signed_hdr.h"), []byte(hdr), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.c"), []byte("int x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"shdr_subkey", "shdr_pub_key"} {
		snip, ok := findStructDefinition(root, name, []string{"target.c"})
		if !ok {
			t.Errorf("struct %s not found via header fallback", name)
			continue
		}
		if !strings.Contains(snip.Path, "signed_hdr.h") {
			t.Errorf("struct %s found in wrong file %s", name, snip.Path)
		}
	}
	if _, ok := findStructDefinition(root, "no_such", nil); ok {
		t.Error("fabricated a snippet for an absent struct")
	}
}

// TestDeterministicEvidenceSnippets_EndToEnd drives the full enrichment
// against the CVE-2026-44362 shape: producer and authority definitions
// resolved through the index (authority's body was THE gap), and BOTH
// structs attached — the table's shdr_pub_key AND the body-referenced
// shdr_subkey, the latter living only in a header.
func TestDeterministicEvidenceSnippets_EndToEnd(t *testing.T) {
	root := t.TempDir()
	runDir := t.TempDir()

	producer := "TEE_Result shdr_load_pub_key(const struct shdr_subkey *subkey, struct shdr_pub_key *key)\n{\n\tkey->max_depth = subkey->max_depth;\n\treturn TEE_SUCCESS;\n}\n"
	authority := "static TEE_Result check_update_version(struct db *db, uint32_t version)\n{\n\tif (version < db->version)\n\t\treturn TEE_ERROR_SECURITY;\n\treturn TEE_SUCCESS;\n}\n"
	hdr := "#pragma once\n\nstruct shdr_subkey {\n\tuint32_t subkey_version;\n};\n\nstruct shdr_pub_key {\n\tuint32_t version;\n};\n"
	files := map[string]string{
		"core/crypto/signed_hdr.c":  producer,
		"core/kernel/ree_fs_ta.c":   authority,
		"core/include/signed_hdr.h": hdr,
	}
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	facts := artifacts.RepoFacts{
		SchemaVersion: "teecheck.repo_facts.v1",
		Capsules: []artifacts.FunctionCapsule{
			{Name: "shdr_load_pub_key", Module: "core/crypto", File: "core/crypto/signed_hdr.c", Line: 1},
			{Name: "check_update_version", Module: "core/kernel", File: "core/kernel/ree_fs_ta.c", Line: 1},
		},
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		t.Fatal(err)
	}
	index := loadFunctionIndex(runDir)
	if len(index) != 2 {
		t.Fatalf("index = %v, want 2 symbols", index)
	}

	fact := artifacts.ToolFact{
		FactID: "trustir-cpp-test",
		Status: trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{
			{Path: "core/crypto/signed_hdr.c", StartLine: 1, Symbol: "shdr_load_pub_key"},
		},
		Findings: []artifacts.ToolFinding{{
			Message: "producer shdr_load_pub_key never propagates rollback field 'version'",
			Related: []artifacts.ToolLocation{
				{Path: "core/kernel/ree_fs_ta.c", Symbol: "check_update_version"},
				{Path: "core/crypto/signed_hdr.c", Symbol: "shdr_load_pub_key"},
			},
		}},
	}
	table := trustirfacts.FactTable{ProducedStructs: []string{"shdr_pub_key"}}

	snippets := deterministicEvidenceSnippets(root, index, fact, &table)
	var gotAuthority, gotProducer, gotProduced, gotConsumed bool
	for _, s := range snippets {
		switch {
		case strings.Contains(s.Content, "check_update_version") && strings.Contains(s.Content, "version < db->version"):
			gotAuthority = true
		case strings.Contains(s.Content, "shdr_load_pub_key") && strings.Contains(s.Content, "max_depth"):
			gotProducer = true
		case strings.Contains(s.Content, "struct shdr_pub_key") && s.Path == "core/include/signed_hdr.h":
			gotProduced = true
		case strings.Contains(s.Content, "struct shdr_subkey") && strings.Contains(s.Content, "subkey_version"):
			gotConsumed = true
		}
	}
	if !gotProducer {
		t.Errorf("producer definition body missing: %+v", snippets)
	}
	if !gotAuthority {
		t.Errorf("authority definition body missing — the exact CVE-2026-44362 gap: %+v", snippets)
	}
	if !gotProduced {
		t.Errorf("produced struct (table-named, header-resident) missing: %+v", snippets)
	}
	if !gotConsumed {
		t.Errorf("consumed struct (body-referenced only) missing: %+v", snippets)
	}
}

// TestDeterministicEvidenceSnippets_AmbiguousNameDeclined (codex-R1
// MEDIUM 4): a name with multiple definition sites and no path from the
// finding yields NO snippet (the wrong body is worse than none); with a
// path, the matching site wins.
func TestDeterministicEvidenceSnippets_AmbiguousNameDeclined(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"a.c", "b.c"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("int helper(void)\n{\n\treturn 1;\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	index := map[string][]functionDef{
		"helper": {{File: "a.c", Line: 1}, {File: "b.c", Line: 1}},
	}
	// Two independent facts (Locations slices must not alias): one with the
	// finding's path, one without.
	factWithPath := artifacts.ToolFact{
		Status:    trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{{Path: "a.c", StartLine: 1, Symbol: "helper"}},
	}
	factNoPath := artifacts.ToolFact{
		Status:    trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{{Path: "", StartLine: 1, Symbol: "helper"}},
	}
	// No path on the finding → ambiguity declined.
	if got := deterministicEvidenceSnippets(root, index, factNoPath, nil); len(got) != 0 {
		t.Errorf("ambiguous name without path must yield no snippet, got %+v", got)
	}
	// Path given → the matching site resolves.
	if got := deterministicEvidenceSnippets(root, index, factWithPath, nil); len(got) != 1 || got[0].Path != "a.c" {
		t.Errorf("path-qualified resolution failed: %+v", got)
	}
}

// TestFindStructDefinition_ExcludedAncestorRoot (codex-R3 MEDIUM): a
// repository living UNDER an ancestor directory named "build" must not
// have its header walk pruned at the root — exclusion judges only
// descendants relative to repoRoot.
func TestFindStructDefinition_ExcludedAncestorRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "build", "repo")
	if err := os.MkdirAll(filepath.Join(root, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "include/t.h"), []byte("struct thing {\n\tint a;\n};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snip, ok := findStructDefinition(root, "thing", nil)
	if !ok {
		t.Fatal("struct not found: the ancestor 'build' directory pruned the repository root")
	}
	if !strings.Contains(snip.Path, "include/t.h") {
		t.Errorf("found in wrong file: %+v", snip)
	}
	// Descendant excluded dirs are still pruned.
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor/v.h"), []byte("struct vendorthing {\n\tint b;\n};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := findStructDefinition(root, "vendorthing", nil); ok {
		t.Error("struct inside a pruned vendor/ descendant must not be found")
	}
}

// TestDeterministicEvidenceSnippets_AttemptCap (codex-R3 LOW + COMMENT):
// with no table, every struct candidate is derived and the attempt cap
// bounds them — six body-referenced structs yield at most
// maxDerivedStructs attachments.
func TestDeterministicEvidenceSnippets_AttemptCap(t *testing.T) {
	root := t.TempDir()
	// Producer body references six structs; all six are defined in a
	// header. Only maxDerivedStructs of them may be attempted.
	var body strings.Builder
	body.WriteString("int producer(void)\n{\n")
	for i := 1; i <= 6; i++ {
		body.WriteString("\tstruct t" + strings.Repeat("0", 2-len(fmt.Sprint(i))) + fmt.Sprint(i) + " x;\n")
	}
	body.WriteString("\treturn 0;\n}\n")
	if err := os.WriteFile(filepath.Join(root, "p.c"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	var hdr strings.Builder
	for i := 1; i <= 6; i++ {
		hdr.WriteString(fmt.Sprintf("struct t%02d {\n\tint f;\n};\n", i))
	}
	if err := os.WriteFile(filepath.Join(root, "p.h"), []byte(hdr.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	index := map[string][]functionDef{"producer": {{File: "p.c", Line: 1}}}
	fact := artifacts.ToolFact{
		Status:    trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{{Path: "p.c", StartLine: 1, Symbol: "producer"}},
	}
	snippets := deterministicEvidenceSnippets(root, index, fact, nil)
	structs := 0
	for _, s := range snippets {
		if strings.Contains(s.Content, "struct t") && s.Path == "p.h" {
			structs++
		}
	}
	if structs != maxDerivedStructs {
		t.Errorf("derived struct attachments = %d, want exactly %d (attempt cap)", structs, maxDerivedStructs)
	}
}

// TestDeterministicEvidenceSnippets_TwoPathQualifiedStatics (codex-R3
// COMMENT): two same-named static functions with distinct finding paths
// both resolve — the (path, name) dedup must not collapse them.
func TestDeterministicEvidenceSnippets_TwoPathQualifiedStatics(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"a.c", "b.c"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("static int helper(int v)\n{\n\treturn v + 1;\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	index := map[string][]functionDef{
		"helper": {{File: "a.c", Line: 1}, {File: "b.c", Line: 1}},
	}
	fact := artifacts.ToolFact{
		Status: trustirfacts.StatusSuccess,
		Findings: []artifacts.ToolFinding{{
			Related: []artifacts.ToolLocation{
				{Path: "a.c", Symbol: "helper"},
				{Path: "b.c", Symbol: "helper"},
			},
		}},
	}
	got := deterministicEvidenceSnippets(root, index, fact, nil)
	if len(got) != 2 {
		t.Fatalf("snippets = %d, want 2 (both statics), got %+v", len(got), got)
	}
	if got[0].Path != "a.c" || got[1].Path != "b.c" {
		t.Errorf("expected a.c then b.c, got %s then %s", got[0].Path, got[1].Path)
	}
}

// TestDeterministicEvidenceSnippets_NoIndexNoTableIsNoOp: nothing to
// resolve and nothing to search yields nil — never an error, never a
// fabricated snippet.
func TestDeterministicEvidenceSnippets_NoIndexNoTableIsNoOp(t *testing.T) {
	if got := deterministicEvidenceSnippets(t.TempDir(), nil, artifacts.ToolFact{}, nil); got != nil {
		t.Errorf("empty inputs must yield nil, got %+v", got)
	}
}
