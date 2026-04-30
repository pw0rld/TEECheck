package stats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// collectReview reads 08_review/review_records.jsonl and produces
// the Phase 1.5 ground-truth metrics: a verdict_counts distribution,
// three explicit rate metrics, three slicings, and a reason_code
// distribution. Returns Present=false when the file is absent — the
// run has not been reviewed yet.
//
// The collector walks sidecar artifacts to enrich each record:
//   - 03_cases/case-NNN.json    → category for ByCategory
//   - 07_arbiter/findings.json  → status for ByArbiterStatus
//   - 06_verifier/verify-NNN.json → ExpertCitationValidation, the
//     authoritative source for ByCitationValidity bucketing
//   - 04_expert/hypothesis-NNN.json → fallback when memo is legacy
//     and lacks ExpertCitationValidation
//
// Records that cannot be paired with a finding fall into "?" buckets
// so the totals still reconcile.
func collectReview(runDir string) ReviewStats {
	var s ReviewStats
	jsonlPath := runfs.ReviewRecordsPath(runDir)
	records, ok := loadReviewRecords(jsonlPath)
	if !ok {
		return s
	}
	if len(records) == 0 {
		// File present but empty — keep Present=false so the
		// printed output suppresses the section.
		return s
	}
	s.Present = true

	// Sidecar 1: case_id → category
	categoryByCase := map[string]string{}
	for _, p := range globOrEmpty(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json")) {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err == nil && pack.CaseID != "" {
			categoryByCase[pack.CaseID] = pack.Category
		}
	}

	// Sidecar 2: arbiter findings (status + index → finding lookup)
	statusByFinding := map[string]string{}
	indexByFinding := map[string]int{}
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err == nil {
		for i, f := range findings.Findings {
			if f.FindingID == "" {
				continue
			}
			statusByFinding[f.FindingID] = f.Status
			indexByFinding[f.FindingID] = i
		}
	}

	// Sidecar 3: verify-NNN.json + hypothesis-NNN.json (per
	// finding index) for citation_validity bucketing
	memos := make([]artifacts.VerificationMemo, len(findings.Findings))
	hyps := make([]artifacts.Hypothesis, len(findings.Findings))
	for i := range findings.Findings {
		_ = runfs.ReadJSON(filepath.Join(runfs.VerifierDir(runDir), fmt.Sprintf("verify-%03d.json", i+1)), &memos[i])
		_ = runfs.ReadJSON(filepath.Join(runfs.ExpertDir(runDir), fmt.Sprintf("hypothesis-%03d.json", i+1)), &hyps[i])
	}

	s.VerdictCounts = map[string]int{}
	s.ByCategory = map[string]ReviewBucketAgg{}
	s.ByArbiterStatus = map[string]ReviewBucketAgg{}
	s.ByCitationValidity = map[string]ReviewBucketAgg{}
	s.ReasonCodes = map[string]int{}

	var tp, fp, nc, dr, nio, skip int

	for _, rec := range records {
		v := artifacts.NormalizeVerdict(rec.Verdict)
		s.VerdictCounts[v]++
		switch v {
		case artifacts.VerdictTruePositive:
			tp++
		case artifacts.VerdictFalsePositive:
			fp++
		case artifacts.VerdictNeedsContext:
			nc++
		case artifacts.VerdictDesignRisk:
			dr++
		case artifacts.VerdictNoIssueObserved:
			nio++
		case artifacts.VerdictSkip:
			skip++
		}
		// reason_code applies to any non-TP verdict; legacy fp_reason
		// only on FP. EffectiveReasonCode collapses the two.
		if v != artifacts.VerdictTruePositive {
			if code := rec.EffectiveReasonCode(); code != "" {
				s.ReasonCodes[code]++
			}
		}
		s.TotalLabeled++

		// Category bucket
		category := categoryByCase[rec.CaseID]
		if category == "" {
			category = "?"
		}
		bucketAdd(s.ByCategory, category, v)

		// Arbiter status bucket
		status := statusByFinding[rec.FindingID]
		if status == "" {
			status = "?"
		}
		bucketAdd(s.ByArbiterStatus, status, v)

		// Citation validity bucket — drive off ExpertCitationValidation
		// when present, fall back to evidence-anchoring otherwise.
		validity := "no_citations"
		if idx, ok := indexByFinding[rec.FindingID]; ok && idx < len(memos) {
			validity = classifyCitationValidity(memos[idx], hyps[idx], findings.Findings[idx])
		}
		bucketAdd(s.ByCitationValidity, validity, v)
	}

	s.CandidateLabeled = tp + fp + nc + dr

	// Three explicit rates. Numerators and denominators are
	// preserved so consumers can detect low-sample rates.
	s.FPRateDefinitive = newRate(fp, tp+fp)
	s.FPRateReviewed = newRate(fp, s.CandidateLabeled)
	s.NonPositiveRate = newRate(fp+nc+dr, s.CandidateLabeled)

	return s
}

// classifyCitationValidity determines the 5-bucket discriminator:
//
//   no_citations    — hypothesis carried no CitedFacts
//   all_valid       — every validation entry is StatusValid
//   partially_valid — at least one valid + at least one not
//   unanchored      — none valid; all entries are StatusUnanchored
//   unresolved      — none valid; mixed unresolved/stale or all
//                     unresolved/stale (the worst-case bucket)
//
// The bucket is computed from VerificationMemo.ExpertCitationValidation
// when present (V1.1.2+ memos). For pre-V1.1.2 memos that carry no
// validation array, the function falls back to inspecting the
// FindingItem.Evidence list — a coarse anchored/unanchored split.
func classifyCitationValidity(memo artifacts.VerificationMemo, hyp artifacts.Hypothesis, f artifacts.FindingItem) string {
	// Modern path: V1.1.2 verifier populates ExpertCitationValidation.
	if len(memo.ExpertCitationValidation) > 0 {
		var valid, unanchored, unresolved, stale int
		for _, cv := range memo.ExpertCitationValidation {
			switch cv.Status {
			case citations.StatusValid:
				valid++
			case citations.StatusUnanchored:
				unanchored++
			case citations.StatusUnresolved:
				unresolved++
			case citations.StatusStale:
				stale++
			}
		}
		total := len(memo.ExpertCitationValidation)
		switch {
		case valid == total:
			return "all_valid"
		case valid > 0:
			return "partially_valid"
		case unanchored == total:
			return "unanchored"
		default:
			// Pure unresolved, pure stale, or any mix that has no
			// valid entries. Bucket as "unresolved" — the most
			// pessimistic non-unanchored failure mode.
			return "unresolved"
		}
	}

	// Legacy fallback: no validation array on the memo. If the
	// hypothesis declares CitedFacts but the verifier didn't
	// validate them, infer from the arbiter Evidence list.
	if len(hyp.CitedFacts) == 0 {
		return "no_citations"
	}
	if findingHasAnchoredEvidence(f) {
		return "all_valid"
	}
	return "unanchored"
}

func newRate(numerator, denominator int) RateMetric {
	rm := RateMetric{Numerator: numerator, Denominator: denominator}
	if denominator > 0 {
		v := float64(numerator) / float64(denominator)
		rm.Value = &v
	}
	return rm
}

func loadReviewRecords(path string) ([]artifacts.ReviewRecord, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var out []artifacts.ReviewRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r artifacts.ReviewRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, true
}

// bucketAdd accumulates a verdict into a named bucket. The bucket
// keeps the full verdict_counts cross-tab — top-level rates carry
// the rate definitions, so per-bucket rates aren't computed (they
// would invite definition drift).
func bucketAdd(m map[string]ReviewBucketAgg, key, verdict string) {
	b := m[key]
	if b.VerdictCounts == nil {
		b.VerdictCounts = map[string]int{}
	}
	b.Total++
	b.VerdictCounts[verdict]++
	m[key] = b
}

// findingHasAnchoredEvidence returns true iff the finding has at
// least one Evidence entry that is NOT prefixed with [unanchored.
// Mirrors arbiter.buildFindingEvidence's tagging convention. Used
// only as a fallback for pre-V1.1.2 memos that carry no
// ExpertCitationValidation array.
func findingHasAnchoredEvidence(f artifacts.FindingItem) bool {
	for _, e := range f.Evidence {
		if !strings.HasPrefix(e, "[unanchored") {
			return true
		}
	}
	return false
}

func globOrEmpty(pattern string) []string {
	out, _ := filepath.Glob(pattern)
	return out
}
