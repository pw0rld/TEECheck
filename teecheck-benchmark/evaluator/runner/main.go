package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type fileSpec struct {
	Path       string `json:"path"`
	Vulnerable string `json:"vulnerable_sha256"`
	Fixed      string `json:"fixed_sha256"`
}

type caseSpec struct {
	Schema             int        `json:"schema"`
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Platform           string     `json:"platform"`
	Repository         string     `json:"repository"`
	VulnerableRevision string     `json:"vulnerable_revision"`
	FixedRevision      string     `json:"fixed_revision"`
	DetectionSurface   string     `json:"detection_surface"`
	Language           string     `json:"language"`
	ScanPaths          []string   `json:"scan_paths"`
	Files              []fileSpec `json:"files"`
}

type oracleSpec struct {
	Schema           int      `json:"schema"`
	ID               string   `json:"id"`
	Status           string   `json:"status"`
	Expected         string   `json:"expected"`
	Weakness         string   `json:"weakness"`
	PrimaryFile      string   `json:"primary_file"`
	// PrimaryLine, when > 0, pins the exploitable line so the matcher can
	// enforce line-level agreement (the Juliet refinement). Optional: oracles
	// that omit it are scored on file + family alone.
	PrimaryLine     int    `json:"primary_line,omitempty"`
	PrimaryFunction string `json:"primary_function"`
	MatchTerms       []string `json:"match_terms"`
	RequiredEvidence []string `json:"required_evidence"`
	FixedEvidence    []string `json:"fixed_evidence"`
	// TWEFamily is the TEE Weakness Entry family this CVE falls under
	// (Flow, Guard, Binding, State, Config, Design, Leakage), or "" when
	// the weakness is outside TWE scope (generic memory-safety, arithmetic,
	// resource, or concurrency bugs that need no TEE trust reasoning).
	TWEFamily string `json:"twe_family"`
	// InTWEScope mirrors TWEFamily != "". A case out of scope is a known
	// design gap, not a scanner failure, so it is scored on its own track.
	InTWEScope bool `json:"in_twe_scope"`
	// CaseKind distinguishes a real vulnerability from a defensive
	// hardening commit (timing, register-state sanitization). Hardening
	// cases are legitimate but harder ground truth; they are reported
	// separately so they cannot silently depress headline recall.
	CaseKind string `json:"case_kind"`
	// ScopeReason is a one-line human justification for the scope/family.
	ScopeReason string `json:"scope_reason"`
	// OracleReview records how trustworthy the primary_file location is,
	// following the ISSTA'25 finding that fix-commit-derived oracles are
	// noisy: a multi-file fix touches mostly collateral, so primary_file must
	// be confirmed as the exploitable file, not a ripple. Single-file fixes
	// are unambiguous; multi-file fixes start pending and are promoted to
	// confirmed or corrected after review.
	OracleReview oracleReview `json:"oracle_review"`
	// LeakageSuspect is true when the case pins a public CVE whose vulnerable
	// and fixed source and patch are public, hence plausibly in the training
	// corpus of the GLM-based scanner. A detection on such a case may reflect
	// memorization rather than reasoning, so the suspect subset is reported
	// separately.
	LeakageSuspect bool `json:"leakage_suspect"`
}

type oracleReview struct {
	LocationProvenance string `json:"location_provenance"`
	PatchFiles         int    `json:"patch_files"`
}

var validLocationProvenance = map[string]bool{
	"single-file-fix":      true,
	"multi-file-pending":   true,
	"multi-file-confirmed": true,
	"multi-file-corrected": true,
}

var validTWEFamilies = map[string]bool{
	"": true, "Flow": true, "Guard": true, "Binding": true,
	"State": true, "Config": true, "Design": true, "Leakage": true,
}

func main() {
	casesDir := flag.String("cases", "datasets", "benchmark dataset directory")
	mode := flag.String("mode", "validate", "validate, evaluate, or score")
	list := flag.Bool("list", false, "list valid case identifiers")
	resultsDir := flag.String("results", "results", "scanner results and score reports directory")
	scannerCommand := flag.String("scanner-command", "", "command template with {input}, {run_dir}, {case}, and {variant} placeholders")
	timeout := flag.Duration("timeout", 30*time.Minute, "timeout for each scanner invocation")
	flag.Parse()

	entries, err := os.ReadDir(*casesDir)
	if err != nil {
		fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fatal(errors.New("no benchmark cases found"))
	}

	failed := false
	var validCases []loadedCase
	for _, name := range names {
		dir := filepath.Join(*casesDir, name)
		if err := validateCase(dir); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", name, err)
			failed = true
			continue
		}
		loaded, err := loadCase(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", name, err)
			failed = true
			continue
		}
		validCases = append(validCases, loaded)
		if *list {
			fmt.Println(name)
		} else if *mode == "validate" {
			fmt.Printf("PASS %s\n", name)
		}
	}
	if failed {
		os.Exit(1)
	}

	switch *mode {
	case "validate":
		return
	case "evaluate":
		if strings.TrimSpace(*scannerCommand) == "" {
			fatal(errors.New("evaluate mode requires -scanner-command"))
		}
		if err := evaluate(validCases, *resultsDir, *scannerCommand, *timeout); err != nil {
			fatal(err)
		}
	case "score":
		if err := scoreAndWrite(validCases, *resultsDir); err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("unsupported mode %q", *mode))
	}
}

func validateCase(dir string) error {
	var c caseSpec
	if err := readJSON(filepath.Join(dir, "case.yaml"), &c); err != nil {
		return err
	}
	var o oracleSpec
	if err := readJSON(filepath.Join(dir, "oracle.yaml"), &o); err != nil {
		return err
	}
	if c.Schema != 1 || o.Schema != 1 {
		return errors.New("unsupported schema")
	}
	if c.ID == "" || c.ID != o.ID || c.ID != filepath.Base(dir) {
		return errors.New("case, oracle, and directory identifiers differ")
	}
	if c.Status != "fixture_ready" {
		return fmt.Errorf("unsupported or missing case status %q", c.Status)
	}
	// Every case is source-backed: it tracks a public CVE with a real upstream
	// repository and revisions, so the vulnerable and fixed source can be
	// traced to the upstream commit.
	if c.Repository == "" || c.VulnerableRevision == "" || c.FixedRevision == "" {
		return errors.New("repository revisions are incomplete")
	}
	if len(c.Files) == 0 || len(c.ScanPaths) == 0 {
		return errors.New("no fixture files or scan paths")
	}
	if o.Expected != "vulnerable_only" || o.Weakness == "" || o.PrimaryFile == "" || o.PrimaryFunction == "" {
		return errors.New("oracle ground truth is incomplete")
	}
	if !validTWEFamilies[o.TWEFamily] {
		return fmt.Errorf("unknown twe_family %q", o.TWEFamily)
	}
	if o.InTWEScope != (o.TWEFamily != "") {
		return fmt.Errorf("in_twe_scope %v disagrees with twe_family %q", o.InTWEScope, o.TWEFamily)
	}
	if o.CaseKind != "vulnerability" && o.CaseKind != "hardening" {
		return fmt.Errorf("case_kind must be vulnerability or hardening, got %q", o.CaseKind)
	}
	if o.ScopeReason == "" {
		return errors.New("scope_reason is required")
	}
	if !validLocationProvenance[o.OracleReview.LocationProvenance] {
		return fmt.Errorf("unknown oracle_review.location_provenance %q", o.OracleReview.LocationProvenance)
	}
	if !containsPath(c.ScanPaths, o.PrimaryFile) {
		return fmt.Errorf("oracle primary file %q is not included in scan_paths", o.PrimaryFile)
	}
	if len(o.MatchTerms) == 0 || len(o.RequiredEvidence) == 0 || len(o.FixedEvidence) == 0 {
		return errors.New("oracle evidence is incomplete")
	}
	if _, err := os.Stat(filepath.Join(dir, "patches", "fix.patch")); err != nil {
		return fmt.Errorf("fix patch: %w", err)
	}
	patchBytes, err := os.ReadFile(filepath.Join(dir, "patches", "fix.patch"))
	if err != nil {
		return fmt.Errorf("read fix patch: %w", err)
	}
	if len(patchBytes) == 0 {
		return errors.New("fix patch is empty")
	}

	for _, scanPath := range c.ScanPaths {
		if scanPath == "" || filepath.IsAbs(scanPath) || strings.Contains(scanPath, "..") {
			return fmt.Errorf("unsafe scan path %q", scanPath)
		}
		for _, variant := range []string{"vulnerable", "fixed"} {
			path := filepath.Join(dir, variant, filepath.FromSlash(scanPath))
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("scan path %s/%s: %w", variant, scanPath, err)
			}
		}
	}

	seen := map[string]bool{}
	changed := 0
	for _, f := range c.Files {
		if f.Path == "" || filepath.IsAbs(f.Path) || strings.Contains(f.Path, "..") {
			return fmt.Errorf("unsafe fixture path %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("duplicate fixture path %q", f.Path)
		}
		seen[f.Path] = true
		vuln := filepath.Join(dir, "vulnerable", filepath.FromSlash(f.Path))
		fixed := filepath.Join(dir, "fixed", filepath.FromSlash(f.Path))
		if err := verifyHash(vuln, f.Vulnerable); err != nil {
			return err
		}
		if err := verifyHash(fixed, f.Fixed); err != nil {
			return err
		}
		if f.Vulnerable != f.Fixed {
			changed++
		}
		if !strings.Contains(string(patchBytes), f.Path) {
			return fmt.Errorf("fix patch does not reference fixture file %q", f.Path)
		}
	}
	if changed == 0 {
		return errors.New("vulnerable and fixed fixtures are identical")
	}
	if !seen[o.PrimaryFile] {
		return fmt.Errorf("oracle primary file %q is absent from fixture", o.PrimaryFile)
	}
	return nil
}

func containsPath(paths []string, want string) bool {
	want = filepath.ToSlash(filepath.Clean(want))
	for _, path := range paths {
		path = filepath.ToSlash(filepath.Clean(path))
		if path == want || strings.HasPrefix(want, path+"/") {
			return true
		}
	}
	return false
}

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func verifyHash(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("hash mismatch for %s: got %s want %s", path, got, want)
	}
	return nil
}

func fatal(err error) {
	if !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, err)
	} else {
		fmt.Fprintf(os.Stderr, "benchmark path does not exist: %v\n", err)
	}
	os.Exit(1)
}
