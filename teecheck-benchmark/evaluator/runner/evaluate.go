package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type loadedCase struct {
	Dir    string
	Case   caseSpec
	Oracle oracleSpec
}

type teecheckFindings struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Findings      []teecheckFinding `json:"findings"`
}

type teecheckFinding struct {
	FindingID string            `json:"finding_id"`
	Status    string            `json:"status"`
	Files     []string          `json:"files"`
	Locations []findingLocation `json:"locations"`
	Summary   string            `json:"summary"`
	Evidence  []string          `json:"evidence"`
}

type findingLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
}

// lineTolerance is how far a finding's line may sit from the oracle's
// primary_line and still count as the same site — wide enough to cover a small
// fix hunk, narrow enough to distinguish unrelated code in the same file.
const lineTolerance = 12

type variantScore struct {
	Variant        string   `json:"variant"`
	Expected       string   `json:"expected"`
	Observed       string   `json:"observed"`
	Classification string   `json:"classification"`
	MatchedFinding string   `json:"matched_finding,omitempty"`
	MatchReasons   []string `json:"match_reasons,omitempty"`
	FindingsPath   string   `json:"findings_path"`
	FindingCount   int      `json:"finding_count"`
}

type caseScore struct {
	CaseID     string       `json:"case_id"`
	TWEFamily  string       `json:"twe_family"`
	InTWEScope bool         `json:"in_twe_scope"`
	CaseKind   string       `json:"case_kind"`
	PairedPass bool         `json:"paired_pass"`
	Vulnerable variantScore `json:"vulnerable"`
	Fixed      variantScore `json:"fixed"`
}

// trackMetrics holds the confusion-matrix totals and derived metrics for
// one slice of the corpus (the whole set, the in-scope subset, one TWE
// family, etc.). Splitting the report this way keeps a scanner's real
// ability from being averaged together with cases it was never designed
// to catch.
type trackMetrics struct {
	Label        string      `json:"label"`
	Cases        int         `json:"cases"`
	Totals       scoreTotals `json:"totals"`
	Errors       int         `json:"errors"`
	Precision    float64     `json:"precision"`
	Recall       float64     `json:"recall"`
	F1           float64     `json:"f1"`
	Specificity  float64     `json:"specificity"`
	PairedPasses int         `json:"paired_passes"`
	PairedRate   float64     `json:"paired_pass_rate"`
}

func (t *trackMetrics) add(cs caseScore) {
	t.Cases++
	addClass(&t.Totals, cs.Vulnerable.Classification)
	addClass(&t.Totals, cs.Fixed.Classification)
	// An ERROR variant (scan crashed / produced no findings.json) is not a
	// TP/FP/FN/TN judgment. It is counted separately so infrastructure
	// failures neither inflate nor deflate precision/recall, but stay
	// visible and can be driven to zero.
	if cs.Vulnerable.Classification == "ERROR" || cs.Fixed.Classification == "ERROR" {
		t.Errors++
	}
	if cs.PairedPass {
		t.PairedPasses++
	}
}

func (t *trackMetrics) finalize() {
	t.Precision = ratio(t.Totals.TP, t.Totals.TP+t.Totals.FP)
	t.Recall = ratio(t.Totals.TP, t.Totals.TP+t.Totals.FN)
	t.Specificity = ratio(t.Totals.TN, t.Totals.TN+t.Totals.FP)
	t.F1 = ratio(2*t.Totals.TP, 2*t.Totals.TP+t.Totals.FP+t.Totals.FN)
	t.PairedRate = ratio(t.PairedPasses, t.Cases)
}

type scoreReport struct {
	Schema      string      `json:"schema"`
	GeneratedAt string      `json:"generated_at"`
	Cases       []caseScore `json:"cases"`

	// Overall is every scored case. In-scope isolates the CVEs whose
	// weakness TEECheck's TWE pipeline is designed to reach; out-of-scope
	// collects the generic memory/arithmetic/resource bugs that are a
	// known design gap, not a scanner failure. Headline capability should
	// be read off InScope, not Overall.
	Overall    trackMetrics            `json:"overall"`
	InScope    trackMetrics            `json:"in_twe_scope"`
	OutOfScope trackMetrics            `json:"out_of_twe_scope"`
	ByFamily   map[string]trackMetrics `json:"by_family"`

	// Flat overall fields retained for backward compatibility with earlier
	// report consumers. They mirror Overall.
	Totals       scoreTotals `json:"totals"`
	Precision    float64     `json:"precision"`
	Recall       float64     `json:"recall"`
	F1           float64     `json:"f1"`
	Specificity  float64     `json:"specificity"`
	PairedPasses int         `json:"paired_passes"`
	PairedRate   float64     `json:"paired_pass_rate"`
}

type scoreTotals struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

func loadCase(dir string) (loadedCase, error) {
	var c caseSpec
	if err := readJSON(filepath.Join(dir, "case.yaml"), &c); err != nil {
		return loadedCase{}, err
	}
	var o oracleSpec
	if err := readJSON(filepath.Join(dir, "oracle.yaml"), &o); err != nil {
		return loadedCase{}, err
	}
	return loadedCase{Dir: dir, Case: c, Oracle: o}, nil
}

func evaluate(cases []loadedCase, resultsDir, commandTemplate string, timeout time.Duration) error {
	for _, c := range cases {
		if c.Case.Status == "pending_source" {
			continue
		}
		for _, variant := range []string{"vulnerable", "fixed"} {
			input, err := filepath.Abs(filepath.Join(c.Dir, variant))
			if err != nil {
				return err
			}
			runDir, err := filepath.Abs(filepath.Join(resultsDir, c.Case.ID, variant))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				return err
			}
			command := expandCommand(commandTemplate, commandValues(c, variant, input, runDir))
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			cmd := exec.CommandContext(ctx, "sh", "-c", command)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("RUN %s/%s\n", c.Case.ID, variant)
			err = cmd.Run()
			cancel()
			// A failed or timed-out scan must not abort the whole batch. It
			// is recorded as an ERROR variant during scoring (missing
			// findings.json) and reported separately, so one crashing scan
			// does not discard the results of every case that ran.
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				fmt.Printf("WARN %s/%s scanner timeout after %s\n", c.Case.ID, variant, timeout)
			case err != nil:
				fmt.Printf("WARN %s/%s scanner failed: %v\n", c.Case.ID, variant, err)
			default:
				if _, err := findFindings(runDir); err != nil {
					fmt.Printf("WARN %s/%s: %v\n", c.Case.ID, variant, err)
				}
			}
		}
	}
	return scoreAndWrite(cases, resultsDir)
}

// commandValues builds the placeholders one scan command is expanded with.
// repository/revision let the scanner be told which upstream project and
// revision the fixture represents: the fixture is a subtree of this
// repository, so git would otherwise report the benchmark's own origin and
// HEAD. Each variant carries its OWN revision — the fact layer keys its cache
// on (repository, commit, operation), so sharing one would make the fixed run
// reuse the vulnerable run's facts and collapse the differential.
func commandValues(c loadedCase, variant, input, runDir string) map[string]string {
	revision := c.Case.VulnerableRevision
	if variant == "fixed" {
		revision = c.Oracle.FixedRevision
	}
	return map[string]string{
		"input":      input,
		"run_dir":    runDir,
		"case":       c.Case.ID,
		"variant":    variant,
		"repository": c.Case.Repository,
		"revision":   revision,
	}
}

func expandCommand(template string, values map[string]string) string {
	out := template
	for key, value := range values {
		out = strings.ReplaceAll(out, "{"+key+"}", shellQuote(value))
	}
	return out
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func scoreAndWrite(cases []loadedCase, resultsDir string) error {
	report, err := buildScore(cases, resultsDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(resultsDir, "score.json")
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	markdownPath := filepath.Join(resultsDir, "score.md")
	if err := os.WriteFile(markdownPath, []byte(renderMarkdown(report)), 0o644); err != nil {
		return err
	}
	printScore(report, path)
	return nil
}

func trackRow(b *strings.Builder, t trackMetrics) {
	fmt.Fprintf(b, "| %s | %d | %d | %d | %d | %d | %d | %.4f | %.4f | %.4f | %.4f | %d/%d |\n",
		t.Label, t.Cases, t.Totals.TP, t.Totals.FP, t.Totals.FN, t.Totals.TN, t.Errors,
		t.Precision, t.Recall, t.F1, t.Specificity, t.PairedPasses, t.Cases)
}

func renderMarkdown(report scoreReport) string {
	var b strings.Builder
	b.WriteString("# TEECheck Benchmark Score\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", report.GeneratedAt)

	b.WriteString("## Metrics by track\n\n")
	b.WriteString("Read scanner capability off **in_twe_scope**. The out_of_twe_scope\n")
	b.WriteString("track is a known design gap (generic memory/arithmetic/resource bugs the\n")
	b.WriteString("TWE pipeline does not target), not a scanner failure.\n\n")
	b.WriteString("| Track | Cases | TP | FP | FN | TN | Err | Precision | Recall | F1 | Specificity | Paired |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	trackRow(&b, report.Overall)
	trackRow(&b, report.InScope)
	trackRow(&b, report.OutOfScope)
	b.WriteString("\n### In-scope by TWE family\n\n")
	b.WriteString("| Family | Cases | TP | FP | FN | TN | Err | Precision | Recall | F1 | Specificity | Paired |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, fam := range []string{"Flow", "Guard", "Binding", "State", "Config", "Design", "Leakage"} {
		if t, ok := report.ByFamily[fam]; ok {
			trackRow(&b, t)
		}
	}

	b.WriteString("\n## Per-case results\n\n")
	b.WriteString("| Case | Family | Scope | Kind | Vulnerable | Fixed | Pair |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, c := range report.Cases {
		pair := "fail"
		if c.PairedPass {
			pair = "pass"
		}
		scope := "out"
		if c.InTWEScope {
			scope = "in"
		}
		fam := c.TWEFamily
		if fam == "" {
			fam = "-"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", c.CaseID, fam, scope, c.CaseKind, c.Vulnerable.Classification, c.Fixed.Classification, pair)
	}
	b.WriteString("\n## Matching Details\n\n")
	for _, c := range report.Cases {
		fmt.Fprintf(&b, "### %s\n\n", c.CaseID)
		fmt.Fprintf(&b, "- Vulnerable: %s, findings=%d", c.Vulnerable.Classification, c.Vulnerable.FindingCount)
		if c.Vulnerable.MatchedFinding != "" {
			fmt.Fprintf(&b, ", matched=%s", c.Vulnerable.MatchedFinding)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "- Fixed: %s, findings=%d", c.Fixed.Classification, c.Fixed.FindingCount)
		if c.Fixed.MatchedFinding != "" {
			fmt.Fprintf(&b, ", matched=%s", c.Fixed.MatchedFinding)
		}
		b.WriteString("\n")
		if len(c.Vulnerable.MatchReasons) > 0 {
			fmt.Fprintf(&b, "- Vulnerable match reasons: %s\n", strings.Join(c.Vulnerable.MatchReasons, ", "))
		}
		if len(c.Fixed.MatchReasons) > 0 {
			fmt.Fprintf(&b, "- Fixed match reasons: %s\n", strings.Join(c.Fixed.MatchReasons, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildScore(cases []loadedCase, resultsDir string) (scoreReport, error) {
	report := scoreReport{Schema: "teecheck.benchmark.score.v2", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	report.Overall.Label = "overall"
	report.InScope.Label = "in_twe_scope"
	report.OutOfScope.Label = "out_of_twe_scope"
	byFamily := map[string]*trackMetrics{}

	for _, c := range cases {
		if c.Case.Status == "pending_source" {
			continue
		}
		vuln, err := scoreVariant(c, "vulnerable", filepath.Join(resultsDir, c.Case.ID, "vulnerable"))
		if err != nil {
			return scoreReport{}, err
		}
		fixed, err := scoreVariant(c, "fixed", filepath.Join(resultsDir, c.Case.ID, "fixed"))
		if err != nil {
			return scoreReport{}, err
		}
		cs := caseScore{
			CaseID:     c.Case.ID,
			TWEFamily:  c.Oracle.TWEFamily,
			InTWEScope: c.Oracle.InTWEScope,
			CaseKind:   c.Oracle.CaseKind,
			Vulnerable: vuln,
			Fixed:      fixed,
		}
		cs.PairedPass = vuln.Classification == "TP" && fixed.Classification == "TN"

		report.Overall.add(cs)
		if cs.InTWEScope {
			report.InScope.add(cs)
			fam := byFamily[cs.TWEFamily]
			if fam == nil {
				fam = &trackMetrics{Label: cs.TWEFamily}
				byFamily[cs.TWEFamily] = fam
			}
			fam.add(cs)
		} else {
			report.OutOfScope.add(cs)
		}
		report.Cases = append(report.Cases, cs)
	}

	report.Overall.finalize()
	report.InScope.finalize()
	report.OutOfScope.finalize()
	report.ByFamily = make(map[string]trackMetrics, len(byFamily))
	for name, fam := range byFamily {
		fam.finalize()
		report.ByFamily[name] = *fam
	}

	// Mirror Overall into the flat backward-compatible fields.
	report.Totals = report.Overall.Totals
	report.Precision = report.Overall.Precision
	report.Recall = report.Overall.Recall
	report.F1 = report.Overall.F1
	report.Specificity = report.Overall.Specificity
	report.PairedPasses = report.Overall.PairedPasses
	report.PairedRate = report.Overall.PairedRate
	return report, nil
}

func scoreVariant(c loadedCase, variant, resultDir string) (variantScore, error) {
	expected := "clean"
	if variant == "vulnerable" {
		expected = "vulnerable"
	}
	path, err := findFindings(resultDir)
	if err != nil {
		// The scan produced no findings.json (crashed, timed out, or never
		// ran). Record it as ERROR so it is reported separately instead of
		// silently becoming a clean/vulnerable verdict or aborting scoring.
		return variantScore{Variant: variant, Expected: expected, Observed: "error", Classification: "ERROR"}, nil
	}
	var findings teecheckFindings
	if err := readJSON(path, &findings); err != nil {
		return variantScore{Variant: variant, Expected: expected, Observed: "error", Classification: "ERROR", FindingsPath: path}, nil
	}
	result := variantScore{Variant: variant, Expected: expected, Observed: "clean", FindingsPath: path, FindingCount: len(findings.Findings)}
	for _, finding := range findings.Findings {
		matched, reasons := matchFinding(c.Oracle, finding)
		if matched {
			result.Observed = "vulnerable"
			result.MatchedFinding = finding.FindingID
			result.MatchReasons = reasons
			break
		}
	}
	if variant == "vulnerable" {
		if result.Observed == "vulnerable" {
			result.Classification = "TP"
		} else {
			result.Classification = "FN"
		}
	} else if result.Observed == "vulnerable" {
		result.Classification = "FP"
	} else {
		result.Classification = "TN"
	}
	return result, nil
}

// detectionStatuses are the verdicts that assert an issue, across both
// pipelines. The legacy arbiter vocabulary (ascending confidence:
// no_issue_observed < needs_review < likely_issue < confirmed_candidate) counts
// only its top two. The deterministic TWE solver emits its own vocabulary; its
// reported-issue statuses (confirmed, violated_candidate, configuration_dependent)
// count too. needs_review / guarded_elsewhere / test_only etc. are not
// detections: on the vulnerable side they are not credited, on the fixed side
// they are the correct quiet outcome rather than a false positive.
var detectionStatuses = map[string]bool{
	// arbiter (LLM) vocabulary
	"likely_issue":        true,
	"confirmed_candidate": true,
	// solver (deterministic TWE) vocabulary
	"confirmed":               true,
	"violated_candidate":      true,
	"configuration_dependent": true,
}

// familyAbbrev maps the family token in a TWE finding id (TWE-<ABBR>-NNN) to
// the oracle's full family name. The scanner tags every finding with the TWE
// entry it evaluated, so this abbreviation is the finding's asserted weakness
// class — the analogue of a CWE id in OWASP Benchmark / NIST Juliet scoring.
var familyAbbrev = map[string]string{
	"FLOW":   "Flow",
	"GUARD":  "Guard",
	"BIND":   "Binding",
	"STATE":  "State",
	"CONFIG": "Config",
	"DESIGN": "Design",
	"LEAK":   "Leakage",
}

var findingIDFamilyRE = regexp.MustCompile(`^TWE-([A-Z]+)-`)

// findingFamily extracts the asserted TWE family from a finding id such as
// "TWE-BIND-001:CVE-2016-6129-...". It returns "" when the id carries no TWE
// family tag (e.g. a legacy arbiter finding), which cannot match an in-scope
// oracle's family.
func findingFamily(id string) string {
	m := findingIDFamilyRE.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(id)))
	if m == nil {
		return ""
	}
	return familyAbbrev[m[1]]
}

// matchFinding decides whether one scanner finding detects the oracle's
// weakness, using the mechanism established by OWASP Benchmark and NIST
// Juliet/SARD: a finding counts only when it lands on the oracle's file AND
// asserts the oracle's weakness class. The class is the TWE family the scanner
// tagged the finding with (the finding id prefix TWE-<FAMILY>-NNN) — the
// analogue of a CWE id — not free-text keyword overlap. Keyword overlap
// conflated unrelated findings that merely mentioned the file, and missed
// correct prose that used different words; both are documented failure modes
// of string-matched oracles.
//
// Line-level agreement (the Juliet refinement) is not enforced yet: the finding
// schema exposes no structured location, so file+family — the OWASP granularity
// of one file to one class — is what can be asserted reliably today.
func matchFinding(oracle oracleSpec, finding teecheckFinding) (bool, []string) {
	status := strings.ToLower(strings.TrimSpace(finding.Status))
	if !detectionStatuses[status] {
		return false, nil
	}
	fileMatch := false
	for _, file := range finding.Files {
		clean := filepath.ToSlash(filepath.Clean(file))
		if clean == oracle.PrimaryFile || strings.HasSuffix(clean, "/"+oracle.PrimaryFile) {
			fileMatch = true
			break
		}
	}
	if !fileMatch {
		return false, nil
	}
	reasons := []string{"primary_file:" + oracle.PrimaryFile}
	// In-scope cases assert a family; the finding must claim the same class.
	// Out-of-scope cases (twe_family == "") have no expected class and the TWE
	// pipeline is not designed to reach them, so file agreement alone is used
	// on that secondary track.
	if oracle.TWEFamily != "" {
		fam := findingFamily(finding.FindingID)
		if fam != oracle.TWEFamily {
			return false, nil
		}
		reasons = append(reasons, "family:"+fam)
	}
	// Line-level agreement (the Juliet refinement) is enforced only when the
	// oracle pins a primary_line: the finding must carry a structured location
	// on the primary file within lineTolerance. Oracles without a line fall
	// back to file+family, so this tightens scoring case-by-case as lines are
	// added without changing any case that has none.
	if oracle.PrimaryLine > 0 {
		if !locationNearby(finding.Locations, oracle.PrimaryFile, oracle.PrimaryLine) {
			return false, nil
		}
		reasons = append(reasons, fmt.Sprintf("line:%d±%d", oracle.PrimaryLine, lineTolerance))
	}
	return true, reasons
}

// locationNearby reports whether any structured finding location lands on the
// oracle's primary file within lineTolerance of the wanted line.
func locationNearby(locs []findingLocation, primaryFile string, want int) bool {
	for _, loc := range locs {
		clean := filepath.ToSlash(filepath.Clean(loc.Path))
		if clean != primaryFile && !strings.HasSuffix(clean, "/"+primaryFile) {
			continue
		}
		d := loc.StartLine - want
		if d < 0 {
			d = -d
		}
		if d <= lineTolerance {
			return true
		}
	}
	return false
}

func findFindings(root string) (string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "findings.json" {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return "", errors.New("no findings.json produced")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple findings.json files: %v", matches)
	}
	return matches[0], nil
}

func addClass(t *scoreTotals, class string) {
	switch class {
	case "TP":
		t.TP++
	case "FP":
		t.FP++
	case "FN":
		t.FN++
	case "TN":
		t.TN++
	}
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return math.Round((float64(numerator)/float64(denominator))*10000) / 10000
}

func printTrack(t trackMetrics) {
	fmt.Printf("%-16s cases=%d TP=%d FP=%d FN=%d TN=%d err=%d precision=%.4f recall=%.4f F1=%.4f specificity=%.4f paired=%d/%d\n",
		t.Label, t.Cases, t.Totals.TP, t.Totals.FP, t.Totals.FN, t.Totals.TN, t.Errors,
		t.Precision, t.Recall, t.F1, t.Specificity, t.PairedPasses, t.Cases)
}

func printScore(report scoreReport, path string) {
	for _, c := range report.Cases {
		scope := "out"
		if c.InTWEScope {
			scope = "in"
		}
		fmt.Printf("CASE %s scope=%s family=%s vulnerable=%s fixed=%s paired=%t\n", c.CaseID, scope, c.TWEFamily, c.Vulnerable.Classification, c.Fixed.Classification, c.PairedPass)
	}
	printTrack(report.Overall)
	printTrack(report.InScope)
	printTrack(report.OutOfScope)
	for _, fam := range []string{"Flow", "Guard", "Binding", "State", "Config", "Design", "Leakage"} {
		if t, ok := report.ByFamily[fam]; ok {
			printTrack(t)
		}
	}
	fmt.Printf("REPORT %s\n", path)
}
