package main

import (
	"strings"
	"testing"
)

// The two variants of a case must report DIFFERENT upstream revisions. The
// fact layer derives its cache key from (repository, commit, operation), so a
// shared revision would make the fixed run reuse the vulnerable run's facts —
// silently collapsing the differential the benchmark exists to measure.
func TestCommandValues_VariantCarriesItsOwnRevision(t *testing.T) {
	c := loadedCase{
		Case: caseSpec{
			ID:                 "CVE-2019-1010292",
			Repository:         "https://github.com/OP-TEE/optee_os",
			VulnerableRevision: "99e8a8cc",
		},
		Oracle: oracleSpec{FixedRevision: "e3adcf56"},
	}

	vuln := commandValues(c, "vulnerable", "/in/vuln", "/out/vuln")
	if vuln["revision"] != "99e8a8cc" {
		t.Errorf("vulnerable revision = %q, want the vulnerable revision", vuln["revision"])
	}
	fixed := commandValues(c, "fixed", "/in/fixed", "/out/fixed")
	if fixed["revision"] != "e3adcf56" {
		t.Errorf("fixed revision = %q, want the fixed revision", fixed["revision"])
	}
	if vuln["revision"] == fixed["revision"] {
		t.Fatal("both variants share a revision; fact-layer cache keys would collide")
	}

	for _, v := range []map[string]string{vuln, fixed} {
		if v["repo_url"] != v["repository"] || v["commit"] != v["revision"] {
			t.Errorf("identity aliases differ: %+v", v)
		}
		if v["repository"] != "https://github.com/OP-TEE/optee_os" {
			t.Errorf("repository = %q, want the upstream OP-TEE URL", v["repository"])
		}
		if v["case"] != "CVE-2019-1010292" {
			t.Errorf("case = %q", v["case"])
		}
	}
	if vuln["input"] != "/in/vuln" || vuln["run_dir"] != "/out/vuln" {
		t.Errorf("input/run_dir not carried through: %+v", vuln)
	}
	if vuln["variant"] != "vulnerable" || fixed["variant"] != "fixed" {
		t.Errorf("variant not carried through")
	}
}

func TestExpandCommand_QuotesAliasesWithoutExpandingValuesAgain(t *testing.T) {
	values := map[string]string{
		"input":    "/fixtures/O'Brien/{commit}",
		"repo_url": "https://example.test/upstream/repo",
		"commit":   "vulnerable-revision",
	}
	got := expandCommand("teecheck run {input} --repo-url {repo_url} --commit {commit}; echo ${HOME}", values)
	want := "teecheck run '/fixtures/O'\\''Brien/{commit}' --repo-url 'https://example.test/upstream/repo' --commit 'vulnerable-revision'; echo ${HOME}"
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestExpandCommand_PreservesUnrelatedShellBraces(t *testing.T) {
	got := expandCommand("teecheck run {input}; echo ${HOME}; awk '{print}'", map[string]string{"input": "/fixture"})
	if got != "teecheck run '/fixture'; echo ${HOME}; awk '{print}'" {
		t.Fatalf("unrelated shell syntax changed: %q", got)
	}
}

func TestScannerEnvironment_OverridesDuplicateIdentity(t *testing.T) {
	got := scannerEnvironment([]string{
		"PATH=/bin", "TEECHECK_REPO_URL=stale", "TEECHECK_COMMIT=stale",
		"TEECHECK_REPO_URL=also-stale", "TEECHECK_COMMIT=also-stale", "OTHER=keep=equal",
	}, "https://example.test/repo", "fixed-revision")
	want := []string{"PATH=/bin", "OTHER=keep=equal", "TEECHECK_REPO_URL=https://example.test/repo", "TEECHECK_COMMIT=fixed-revision"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("environment = %q, want %q", got, want)
	}
}
