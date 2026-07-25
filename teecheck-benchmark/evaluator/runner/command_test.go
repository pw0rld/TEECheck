package main

import "testing"

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
