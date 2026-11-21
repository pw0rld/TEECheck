package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the test binary as a scanner stand-in. It accepts only the input/output
// paths and reads upstream identity from its environment, as teecheck does for
// a bare local-fixture invocation.
func TestScannerIdentityHelperProcess(t *testing.T) {
	if os.Getenv("TEECHECK_TEST_IDENTITY_HELPER") != "1" {
		return
	}
	args := os.Args
	if len(args) < 3 {
		t.Fatal("scanner helper requires input and output paths")
	}
	input, output := args[len(args)-2], args[len(args)-1]
	if _, err := os.Stat(filepath.Join(input, "fixture.c")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(input, ".git")); !os.IsNotExist(err) {
		t.Fatalf("expected a fixture without Git metadata, got %v", err)
	}
	fixture := filepath.Join(output, "fixture-output")
	writeValidatedFindings(t, fixture, "identity-case", "fixed", nil)
	bundle := filepath.Join(fixture, "identity-case", "fixed", "attempts", "fixture-attempt", "scan")
	manifestPath := filepath.Join(bundle, "00_manifest.json")
	var manifest map[string]any
	if err := readJSON(manifestPath, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["repo_url"] = os.Getenv("TEECHECK_REPO_URL")
	manifest["commit"] = os.Getenv("TEECHECK_COMMIT")
	for key, variable := range map[string]string{"repo_url": "TEECHECK_TEST_WRONG_REPOSITORY", "commit": "TEECHECK_TEST_WRONG_COMMIT"} {
		if value := os.Getenv(variable); value != "" {
			manifest[key] = value
		}
	}
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bundle, filepath.Join(output, "scan")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(fixture); err != nil {
		t.Fatal(err)
	}
}

func TestRunScannerAttempt_LocalFixtureInheritsVariantIdentity(t *testing.T) {
	c := loadedCase{
		Dir: t.TempDir(),
		Case: caseSpec{
			ID: "identity-case", Repository: "https://example.test/upstream/repo", VulnerableRevision: "vulnerable-revision",
		},
		Oracle: oracleSpec{FixedRevision: "fixed-revision"},
	}
	for _, variant := range []string{"vulnerable", "fixed"} {
		input := filepath.Join(c.Dir, variant)
		if err := os.MkdirAll(input, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(input, "fixture.c"), []byte("int fixture;\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEECHECK_TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEECHECK_REPO_URL", "stale-parent-repository")
	t.Setenv("TEECHECK_COMMIT", "stale-parent-revision")
	t.Setenv("TEECHECK_TEST_WRONG_REPOSITORY", "")
	t.Setenv("TEECHECK_TEST_WRONG_COMMIT", "")
	command := shellQuote(binary) + " -test.run=^TestScannerIdentityHelperProcess$ -- {input} {run_dir}"
	for _, tc := range []struct {
		name, variant, wrongRepository, wrongCommit, wantError string
	}{
		{name: "vulnerable inherits upstream identity", variant: "vulnerable"},
		{name: "fixed inherits its own revision", variant: "fixed"},
		{name: "wrong repository rejected", variant: "fixed", wrongRepository: "https://example.test/wrong/repo", wantError: "scanner repository"},
		{name: "wrong revision rejected", variant: "fixed", wrongCommit: "vulnerable-revision", wantError: "scanner revision"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEECHECK_TEST_WRONG_REPOSITORY", tc.wrongRepository)
			t.Setenv("TEECHECK_TEST_WRONG_COMMIT", tc.wrongCommit)
			output := t.TempDir()
			if err := runScannerAttempt(c, tc.variant, output, command, 10*time.Second); err != nil {
				t.Fatal(err)
			}
			_, _, report, err := selectedAttempt(c, tc.variant, output)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("wrong identity accepted or unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantCommit := c.Case.VulnerableRevision
			if tc.variant == "fixed" {
				wantCommit = c.Oracle.FixedRevision
			}
			if report.Repository != c.Case.Repository || report.Commit != wantCommit {
				t.Fatalf("wrong inherited identity: repository=%q commit=%q", report.Repository, report.Commit)
			}
		})
	}
}
