package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// abbrevForFamily reverses familyAbbrev so tests can synthesize a finding id
// that asserts a given family, the way the scanner tags real findings.
func abbrevForFamily(t *testing.T, family string) string {
	t.Helper()
	for abbr, full := range familyAbbrev {
		if full == family {
			return abbr
		}
	}
	t.Fatalf("no abbreviation for family %q", family)
	return ""
}

// findingIDFor builds a finding id that asserts the oracle's class, mirroring
// the scanner's "TWE-<FAMILY>-NNN:<slice>" identifiers. Out-of-scope oracles
// carry no family, so an untagged id is used.
func findingIDFor(t *testing.T, o oracleSpec) string {
	t.Helper()
	if o.TWEFamily == "" {
		return "finding-1"
	}
	return "TWE-" + abbrevForFamily(t, o.TWEFamily) + "-001:" + o.ID
}

func TestBuildScorePairedResults(t *testing.T) {
	cases := loadRepositoryCases(t)
	results := t.TempDir()
	for _, c := range cases {
		writeFindings(t, results, c.Case.ID, "vulnerable", []teecheckFinding{{
			FindingID: findingIDFor(t, c.Oracle),
			Status:    "confirmed_candidate",
			Files:     []string{c.Oracle.PrimaryFile},
			Summary:   "weakness on the oracle file, tagged with the oracle family",
		}})
		writeFindings(t, results, c.Case.ID, "fixed", nil)
	}
	report, err := buildScore(cases, results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals != (scoreTotals{TP: len(cases), TN: len(cases)}) {
		t.Fatalf("totals=%+v", report.Totals)
	}
	if report.Precision != 1 || report.Recall != 1 || report.F1 != 1 || report.Specificity != 1 || report.PairedRate != 1 {
		t.Fatalf("metrics=%+v", report)
	}
}

func TestBuildScoreReportsFalseNegativeAndFalsePositive(t *testing.T) {
	cases := loadRepositoryCases(t)[:1]
	c := cases[0]
	results := t.TempDir()
	writeFindings(t, results, c.Case.ID, "vulnerable", nil)
	writeFindings(t, results, c.Case.ID, "fixed", []teecheckFinding{{
		FindingID: findingIDFor(t, c.Oracle),
		Status:    "confirmed_candidate",
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "same weakness class reported on the fixed variant",
	}})
	report, err := buildScore(cases, results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals != (scoreTotals{FP: 1, FN: 1}) {
		t.Fatalf("totals=%+v", report.Totals)
	}
	if report.Cases[0].PairedPass {
		t.Fatal("pair unexpectedly passed")
	}
}

// TestMatchFindingRequiresFamily: for an in-scope case, a finding on the right
// file whose id carries no family tag (or the wrong one) must not match — the
// mechanism is file AND class, not file alone.
func TestMatchFindingRequiresFamily(t *testing.T) {
	var c loadedCase
	for _, cand := range loadRepositoryCases(t) {
		if cand.Oracle.TWEFamily != "" {
			c = cand
			break
		}
	}
	if c.Oracle.TWEFamily == "" {
		t.Skip("no in-scope case available")
	}
	// Untagged id on the right file: no class asserted.
	if matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Status:    "confirmed_candidate",
		FindingID: "finding-1",
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "issue in the same file but no family tag",
	}); matched {
		t.Fatal("file-only (untagged) finding must not satisfy an in-scope oracle")
	}
	// Wrong family on the right file.
	wrong := "Guard"
	if c.Oracle.TWEFamily == wrong {
		wrong = "Flow"
	}
	if matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Status:    "confirmed_candidate",
		FindingID: "TWE-" + abbrevForFamily(t, wrong) + "-001:x",
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "right file, wrong weakness class",
	}); matched {
		t.Fatalf("family %q on a %q oracle must not match", wrong, c.Oracle.TWEFamily)
	}
}

// TestMatchFindingAcceptsFileAndFamily: right file + right class = detection.
func TestMatchFindingAcceptsFileAndFamily(t *testing.T) {
	var c loadedCase
	for _, cand := range loadRepositoryCases(t) {
		if cand.Oracle.TWEFamily != "" {
			c = cand
			break
		}
	}
	if c.Oracle.TWEFamily == "" {
		t.Skip("no in-scope case available")
	}
	matched, reasons := matchFinding(c.Oracle, teecheckFinding{
		Status:    "confirmed_candidate",
		FindingID: findingIDFor(t, c.Oracle),
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "weakness of the oracle class on the oracle file",
	})
	if !matched {
		t.Fatalf("file+family should match; reasons=%v", reasons)
	}
}

// TestMatchFindingLineRefinement: when the oracle pins primary_line, a finding
// must carry a structured location on the primary file within tolerance; a
// finding with no location, or a location too far away, fails. An oracle
// without primary_line ignores location entirely (backward compatible).
func TestMatchFindingLineRefinement(t *testing.T) {
	var c loadedCase
	for _, cand := range loadRepositoryCases(t) {
		if cand.Oracle.TWEFamily != "" {
			c = cand
			break
		}
	}
	if c.Oracle.TWEFamily == "" {
		t.Skip("no in-scope case available")
	}
	base := teecheckFinding{
		Status:    "confirmed_candidate",
		FindingID: findingIDFor(t, c.Oracle),
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "weakness of the oracle class on the oracle file",
	}

	// No primary_line: location is ignored, file+family matches.
	oNoLine := c.Oracle
	oNoLine.PrimaryLine = 0
	if matched, _ := matchFinding(oNoLine, base); !matched {
		t.Fatal("without primary_line, file+family must still match")
	}

	// primary_line set, finding has a location within tolerance -> match.
	o := c.Oracle
	o.PrimaryLine = 100
	near := base
	near.Locations = []findingLocation{{Path: c.Oracle.PrimaryFile, StartLine: 100 + lineTolerance}}
	if matched, _ := matchFinding(o, near); !matched {
		t.Fatalf("location within ±%d of primary_line must match", lineTolerance)
	}

	// Location too far away -> no match.
	far := base
	far.Locations = []findingLocation{{Path: c.Oracle.PrimaryFile, StartLine: 100 + lineTolerance + 5}}
	if matched, _ := matchFinding(o, far); matched {
		t.Fatal("location outside tolerance must not match when primary_line is set")
	}

	// primary_line set but finding carries no structured location -> no match.
	if matched, _ := matchFinding(o, base); matched {
		t.Fatal("no structured location must not match when primary_line is set")
	}
}

func TestFindingFamily(t *testing.T) {
	cases := map[string]string{
		"TWE-BIND-001:TWE-BIND-0001-registry": "Binding",
		"TWE-GUARD-001:CVE-2016-6129-rsa":     "Guard",
		"TWE-CONFIG-002:x":                    "Config",
		"finding-1":                           "",
		"":                                    "",
		"TWE-UNKNOWN-001:x":                   "",
	}
	for id, want := range cases {
		if got := findingFamily(id); got != want {
			t.Errorf("findingFamily(%q)=%q want %q", id, got, want)
		}
	}
}

func TestMatchFindingRequiresAssertedStatus(t *testing.T) {
	var c loadedCase
	for _, cand := range loadRepositoryCases(t) {
		if cand.Oracle.TWEFamily != "" {
			c = cand
			break
		}
	}
	if c.Oracle.TWEFamily == "" {
		t.Skip("no in-scope case available")
	}
	id := findingIDFor(t, c.Oracle)
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"confirmed_candidate", true},
		{"likely_issue", true},
		{"needs_review", false},
		{"no_issue_observed", false},
		{"", false},
	} {
		matched, _ := matchFinding(c.Oracle, teecheckFinding{
			Status:    tc.status,
			FindingID: id,
			Files:     []string{c.Oracle.PrimaryFile},
			Summary:   "weakness of the oracle class on the oracle file",
		})
		if matched != tc.want {
			t.Fatalf("status %q: matched=%v want %v", tc.status, matched, tc.want)
		}
	}
}

func TestScoreVariantMissingFindingsIsError(t *testing.T) {
	c := loadRepositoryCases(t)[0]
	vs, err := scoreVariant(c, "vulnerable", t.TempDir()) // empty dir, no findings.json
	if err != nil {
		t.Fatalf("missing findings should not error: %v", err)
	}
	if vs.Classification != "ERROR" {
		t.Fatalf("classification=%q want ERROR", vs.Classification)
	}
}

func TestMatchFindingIgnoresExplicitNoIssue(t *testing.T) {
	c := loadRepositoryCases(t)[0]
	matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Status:    "no_issue_observed",
		FindingID: findingIDFor(t, c.Oracle),
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   "weakness of the oracle class on the oracle file",
	})
	if matched {
		t.Fatal("no_issue_observed must not be scored as a vulnerability")
	}
}

func TestContainsPathAcceptsDirectoryScanRoot(t *testing.T) {
	if !containsPath([]string{"syscall"}, "syscall/devices/hostsock/hostsock.c") {
		t.Fatal("directory scan root should cover the oracle primary file")
	}
	if containsPath([]string{"syscall/devices/hostsock"}, "syscall/socket.c") {
		t.Fatal("unrelated sibling must not be covered by a directory scan root")
	}
}

func loadRepositoryCases(t *testing.T) []loadedCase {
	t.Helper()
	root := filepath.Join("..", "..", "datasets")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var cases []loadedCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := loadCase(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if c.Case.Status == "pending_source" {
			continue
		}
		cases = append(cases, c)
	}
	return cases
}

func writeFindings(t *testing.T, root, caseID, variant string, findings []teecheckFinding) {
	t.Helper()
	dir := filepath.Join(root, caseID, variant, "07_arbiter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(teecheckFindings{SchemaVersion: "teecheck.findings.v2", RunID: caseID + "-" + variant, Findings: findings})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
