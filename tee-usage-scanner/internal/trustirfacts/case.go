package trustirfacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CaseRevisions is the subset of a benchmark fixture's case.yaml +
// oracle.yaml this package needs to build a differential (vulnerable vs.
// fixed) database pair: the repository and the two pinned commits.
//
// case.yaml is JSON despite its extension (see
// internal/preprocessor/benchmark_corpus_test.go's identical note) — this
// mirrors that established reading convention rather than introducing a
// YAML parser this package would otherwise not need.
//
// NOTE on a survey correction: the merge design (§23.3) states
// "vulnerable_revision/fixed_revision" both come from case.yaml. Across the
// present benchmark corpus (teecheck-benchmark/datasets/*), only
// vulnerable_revision lives in case.yaml — fixed_revision lives in
// oracle.yaml (see e.g. datasets/CVE-2026-44362/{case,oracle}.yaml). This
// reader accepts fixed_revision from either file, preferring case.yaml if
// both are set, so it keeps working if that split is later corrected
// upstream without code changes here.
type CaseRevisions struct {
	Repository         string
	VulnerableRevision string
	FixedRevision      string
}

// LoadCaseRevisions reads fixtureDir/case.yaml (and, for fixed_revision,
// fixtureDir/oracle.yaml) and returns the repository + pinned commits a
// vulnerable/fixed differential run needs. It does not itself decide which
// revision to analyze — callers pick VulnerableRevision or FixedRevision and
// set it as Request.Commit.
func LoadCaseRevisions(fixtureDir string) (CaseRevisions, error) {
	var out CaseRevisions

	caseData, err := os.ReadFile(filepath.Join(fixtureDir, "case.yaml"))
	if err != nil {
		return CaseRevisions{}, fmt.Errorf("read case.yaml: %w", err)
	}
	var c struct {
		Repository         string `json:"repository"`
		VulnerableRevision string `json:"vulnerable_revision"`
		FixedRevision      string `json:"fixed_revision"`
	}
	if err := json.Unmarshal(caseData, &c); err != nil {
		return CaseRevisions{}, fmt.Errorf("parse case.yaml: %w", err)
	}
	out.Repository = c.Repository
	out.VulnerableRevision = c.VulnerableRevision
	out.FixedRevision = c.FixedRevision

	if out.FixedRevision == "" {
		if oracleData, err := os.ReadFile(filepath.Join(fixtureDir, "oracle.yaml")); err == nil {
			var o struct {
				FixedRevision string `json:"fixed_revision"`
			}
			if err := json.Unmarshal(oracleData, &o); err != nil {
				return CaseRevisions{}, fmt.Errorf("parse oracle.yaml: %w", err)
			}
			out.FixedRevision = o.FixedRevision
		}
	}

	if out.Repository == "" || out.VulnerableRevision == "" {
		return CaseRevisions{}, fmt.Errorf("case.yaml at %s has no repository/vulnerable_revision", fixtureDir)
	}
	return out, nil
}
