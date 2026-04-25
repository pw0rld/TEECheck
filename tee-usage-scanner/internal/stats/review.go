package stats

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// collectReview reads 08_review/review_records.jsonl (the Phase 1
// ground-truth labels) and produces TP/FP/NMC counts plus three
// slicings: by case category, by arbiter status, by citation
// validity bucket. Returns Present=false when the file is absent
// — the run has not been reviewed yet.
//
// The collector also reads case packs and the arbiter findings.json
// so it can map each review record to its category (from the case)
// and its arbiter status (from the finding). When a record cannot
// be paired with a case or finding, the unknowns drop into "?"
// buckets so the totals still reconcile.
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

	// Sidecar: case_id → category, finding_id → status, finding has
	// any anchored citation.
	categoryByCase := map[string]string{}
	for _, p := range globOrEmpty(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json")) {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err == nil && pack.CaseID != "" {
			categoryByCase[pack.CaseID] = pack.Category
		}
	}
	statusByFinding := map[string]string{}
	anchoredByFinding := map[string]bool{}
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err == nil {
		for _, f := range findings.Findings {
			if f.FindingID == "" {
				continue
			}
			statusByFinding[f.FindingID] = f.Status
			anchoredByFinding[f.FindingID] = findingHasAnchoredEvidence(f)
		}
	}

	s.ByCategory = map[string]ReviewBucketAgg{}
	s.ByArbiterStatus = map[string]ReviewBucketAgg{}
	s.ByCitationValidity = map[string]ReviewBucketAgg{}
	s.FPReasons = map[string]int{}

	for _, rec := range records {
		v := artifacts.NormalizeVerdict(rec.Verdict)
		switch v {
		case artifacts.VerdictTruePositive:
			s.TPCount++
		case artifacts.VerdictFalsePositive:
			s.FPCount++
			if rec.FPReason != "" {
				s.FPReasons[rec.FPReason]++
			}
		case artifacts.VerdictNeedsMoreContext:
			s.NMCCount++
		case artifacts.VerdictSkip:
			s.SkipCount++
		}
		s.TotalReviewed++

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

		// Citation validity bucket
		validity := "unanchored"
		if anchoredByFinding[rec.FindingID] {
			validity = "validated"
		}
		bucketAdd(s.ByCitationValidity, validity, v)
	}

	// Finalize FP rate (definitive labels only).
	denom := s.TPCount + s.FPCount
	if denom > 0 {
		s.FPRate = float64(s.FPCount) / float64(denom)
	}
	for k, b := range s.ByCategory {
		b.FPRate = bucketFPRate(b)
		s.ByCategory[k] = b
	}
	for k, b := range s.ByArbiterStatus {
		b.FPRate = bucketFPRate(b)
		s.ByArbiterStatus[k] = b
	}
	for k, b := range s.ByCitationValidity {
		b.FPRate = bucketFPRate(b)
		s.ByCitationValidity[k] = b
	}
	return s
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

func bucketAdd(m map[string]ReviewBucketAgg, key, verdict string) {
	b := m[key]
	b.Total++
	switch verdict {
	case artifacts.VerdictTruePositive:
		b.TP++
	case artifacts.VerdictFalsePositive:
		b.FP++
	case artifacts.VerdictNeedsMoreContext:
		b.NMC++
	}
	m[key] = b
}

func bucketFPRate(b ReviewBucketAgg) float64 {
	denom := b.TP + b.FP
	if denom == 0 {
		return 0
	}
	return float64(b.FP) / float64(denom)
}

// findingHasAnchoredEvidence returns true iff the finding has at
// least one Evidence entry that is NOT prefixed with [unanchored.
// Mirrors arbiter.buildFindingEvidence's tagging convention.
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
