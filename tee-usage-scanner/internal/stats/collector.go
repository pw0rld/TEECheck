package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Collect reads every stage artifact under runDir and returns an
// aggregated RunStats. Missing stages produce zero-valued sub-structs
// with Present=false, not errors — so this works on partial runs
// (e.g. a run that crashed before arbiter).
//
// repoRoot is optional. When non-empty and the directory exists, the
// collector will grep candidate paths/symbols against it to compute
// hallucination rates. When empty, those rates are reported as 1.0
// (assumed valid) so you can still collect stats for runs where the
// original repo checkout is no longer available.
func Collect(runDir, repoRoot string) (*RunStats, error) {
	if runDir == "" {
		return nil, fmt.Errorf("runDir is required")
	}
	if _, err := os.Stat(runDir); err != nil {
		return nil, fmt.Errorf("run dir: %w", err)
	}

	rs := &RunStats{
		SchemaVersion: "teecheck.run_stats.v1",
		RunDir:        runDir,
	}

	if manifest, err := runfs.LoadManifest(runDir); err == nil {
		rs.RunID = manifest.RunID
	}

	rs.Planner = collectPlanner(runDir, repoRoot)
	rs.Cases = collectCases(runDir)
	rs.Expert = collectExpert(runDir, repoRoot)
	rs.Challenger = collectChallenger(runDir)
	rs.Verifier = collectVerifier(runDir)
	rs.Arbiter = collectArbiter(runDir, rs.Verifier.MemoCount)
	rs.Review = collectReview(runDir)
	rs.Overall = computeOverall(rs)
	rs.Source = computeOverallSource(rs)
	return rs, nil
}

// computeOverallSource summarizes which input drove the run's stats.
//
// As of v1 infrastructure complete, the typical observed values are:
//   - "events"    : a run where the planner is the only populated
//                   stage (e.g. an interrupted run, or a unit-test
//                   fixture) and that planner folded from events.jsonl
//   - "mixed"     : events.jsonl present, planner folded from it,
//                   downstream stages (expert/challenger/verifier/
//                   arbiter) still come from stage JSON. This is
//                   the common case for end-to-end runs today.
//   - "artifacts" : no events.jsonl available — legacy run from
//                   before the events stream existed.
//
// "events" becomes the common case once the four audit agents are
// also event-instrumented. Until then, the stage JSON path is
// authoritative for those agents and "mixed" is the expected label
// for any new full pipeline run.
func computeOverallSource(rs *RunStats) string {
	plannerSource := rs.Planner.Source
	otherStagesPresent := rs.Cases.Present || rs.Expert.Present ||
		rs.Challenger.Present || rs.Verifier.Present || rs.Arbiter.Present

	switch plannerSource {
	case "events":
		if otherStagesPresent {
			return "mixed"
		}
		return "events"
	case "artifacts":
		return "artifacts"
	default:
		// planner not present
		if otherStagesPresent {
			return "artifacts"
		}
		return ""
	}
}

func collectPlanner(runDir, repoRoot string) PlannerStats {
	var s PlannerStats
	s.ActionMix = map[string]int{}

	var bundle artifacts.EvidenceBundle
	if err := runfs.ReadJSON(runfs.EvidenceBundlePath(runDir), &bundle); err != nil {
		return s
	}
	s.Present = true
	s.CandidateCount = len(bundle.Candidates)
	s.TerminationReason = bundle.PlannerMeta.TerminationReason
	s.RoundsUsed = bundle.PlannerMeta.RoundsUsed
	s.RoundsBudget = bundle.PlannerMeta.RoundsBudget
	s.TokensUsed = bundle.PlannerMeta.TokensUsed
	s.WallClockMs = bundle.PlannerMeta.WallClockMs

	// Diversity: count unique top-level directories across all
	// candidate paths.
	topDirs := map[string]bool{}
	for _, c := range bundle.Candidates {
		for _, p := range c.Paths {
			top := strings.Split(filepath.ToSlash(p), "/")[0]
			if top != "" {
				topDirs[top] = true
			}
		}
	}
	s.DiversityIndex = len(topDirs)

	// Path / symbol validity: if we have a repo root, verify every
	// candidate path exists and every symbol can be grep'd inside its
	// file. Otherwise assume all valid (we can't prove otherwise).
	if repoRoot != "" {
		if _, err := os.Stat(repoRoot); err == nil {
			validPaths := 0
			totalPaths := 0
			validSyms := 0
			totalSyms := 0
			for _, c := range bundle.Candidates {
				for _, p := range c.Paths {
					totalPaths++
					abs := filepath.Join(repoRoot, p)
					data, err := os.ReadFile(abs)
					if err != nil {
						s.HallucinatedPaths = append(s.HallucinatedPaths, p)
						// paths that don't exist also mean symbols can't be validated
						totalSyms += len(c.Symbols)
						for _, sym := range c.Symbols {
							s.HallucinatedSymbols = append(s.HallucinatedSymbols, p+"::"+sym)
						}
						continue
					}
					validPaths++
					content := string(data)
					for _, sym := range c.Symbols {
						totalSyms++
						if sym == "" || strings.Contains(content, sym) {
							validSyms++
						} else {
							s.HallucinatedSymbols = append(s.HallucinatedSymbols, p+"::"+sym)
						}
					}
				}
			}
			s.PathValidityRate = ratio(validPaths, totalPaths)
			s.SymbolValidityRate = ratio(validSyms, totalSyms)
		} else {
			s.PathValidityRate = 1.0
			s.SymbolValidityRate = 1.0
		}
	} else {
		s.PathValidityRate = 1.0
		s.SymbolValidityRate = 1.0
	}

	// Try events.jsonl first. When the planner emitted events
	// (commit 2 onwards) we prefer them — they directly reflect
	// what was actually executed (excluding loop-detector rejects)
	// and they survive incremental schema changes to RoundRecord.
	if fold, ok, _ := foldPlannerEvents(runDir); ok {
		s.Source = "events"
		// rounds_used and tokens_used from the bundle are already
		// authoritative for completed runs, but the bundle records
		// the budget's view. The events fold is the executed view.
		// Prefer events when they disagree.
		if fold.RoundsUsed > 0 {
			s.RoundsUsed = fold.RoundsUsed
		}
		if fold.TokensUsed > 0 {
			s.TokensUsed = fold.TokensUsed
		}
		s.ActionMix = fold.ActionMix
		s.TokensByRound = fold.TokensByRound
		return s
	}

	// Fallback: action mix + per-round token trace from rounds.jsonl.
	s.Source = "artifacts"
	rounds, _ := loadRounds(runfs.RoundsLogPath(runDir))
	for _, r := range rounds {
		for _, a := range r.Actions {
			s.ActionMix[a.Name]++
		}
		s.TokensByRound = append(s.TokensByRound, r.TokensIn+r.TokensOut)
	}
	return s
}

func loadRounds(path string) ([]artifacts.RoundRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []artifacts.RoundRecord
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r artifacts.RoundRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func collectCases(runDir string) CasesStats {
	var s CasesStats
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil || len(paths) == 0 {
		return s
	}
	s.Present = true
	s.CaseCount = len(paths)

	var snippetTotals []int
	symbolsTotal := 0
	symbolsCovered := 0
	for _, p := range paths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err != nil {
			continue
		}
		// Snippet line count
		lines := 0
		for _, sn := range pack.Snippets {
			if sn.EndLine > sn.StartLine {
				lines += sn.EndLine - sn.StartLine + 1
			} else {
				lines += strings.Count(sn.Content, "\n") + 1
			}
		}
		snippetTotals = append(snippetTotals, lines)

		// Symbol coverage: how many target symbols appear anywhere in
		// the pack's snippet contents
		concat := ""
		for _, sn := range pack.Snippets {
			concat += sn.Content + "\n"
		}
		for _, sym := range pack.TargetSymbols {
			symbolsTotal++
			if sym != "" && strings.Contains(concat, sym) {
				symbolsCovered++
			}
		}
		if len(pack.ExpectedObligations) > 0 {
			s.ObligationsAttached++
		}
	}
	s.SnippetLineTotalP50 = percentile(snippetTotals, 50)
	s.SnippetLineTotalMean = mean(snippetTotals)
	s.SymbolCoverageRate = ratio(symbolsCovered, symbolsTotal)
	return s
}

// collectExpert is the typed-citation entry point.
//
// CitationRate counts hypotheses with at least one validated
// CitedBytes — "did the agent actually cite anything that holds up
// against the live repo?". CitationValidityRate is the
// finer-grained signal: of all citations the agent attempted, what
// fraction still validate? A high CitationRate with low
// CitationValidityRate flags an agent that cites freely but whose
// citations drift quickly under repo changes.
//
// repoRoot is required for validation. When empty (or repoRoot does
// not exist on disk), citations are treated as unvalidated and both
// rates are reported as zero — same shape as legacy hypotheses
// without a Cited field, so the metric stays interpretable.
func collectExpert(runDir, repoRoot string) ExpertStats {
	var s ExpertStats
	paths, _ := filepath.Glob(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-*.json"))
	if len(paths) == 0 {
		return s
	}
	s.Present = true
	s.HypothesisCount = len(paths)

	canValidate := repoRoot != ""
	if canValidate {
		if _, err := os.Stat(repoRoot); err != nil {
			canValidate = false
		}
	}

	hypothesesWithValidCite := 0
	var allCitations, validCitations int
	var lengths []int
	var factCounts []int
	for _, p := range paths {
		var h artifacts.Hypothesis
		if err := runfs.ReadJSON(p, &h); err != nil {
			continue
		}
		body := h.Summary + " " + h.SuspectedIssue
		lengths = append(lengths, len(strings.Fields(body)))
		factCounts = append(factCounts, len(h.SupportingFacts))

		// Prefer the structured CitedFacts when present (v1.1.1+).
		// Fall back to the flat Cited pool for legacy hypotheses
		// or for heuristic-mode runs that did not populate the
		// per-fact list. The two paths produce identical numbers
		// when CitedFacts is correctly flattened into Cited (which
		// expert.RunWithEvents does), but the explicit branch
		// avoids double-counting when both fields are present.
		var citePool []citations.CitedBytes
		if len(h.CitedFacts) > 0 {
			for _, f := range h.CitedFacts {
				citePool = append(citePool, f.Cited...)
			}
		} else {
			citePool = h.Cited
		}
		hadValid := false
		for _, c := range citePool {
			allCitations++
			if !canValidate {
				continue
			}
			if err := citations.Validate(c, repoRoot); err == nil {
				validCitations++
				hadValid = true
			}
		}
		if hadValid {
			hypothesesWithValidCite++
		}
	}
	s.CitationRate = ratio(hypothesesWithValidCite, len(paths))
	s.CitationValidityRate = ratio(validCitations, allCitations)
	s.HypothesisLenP50 = percentile(lengths, 50)
	s.HypothesisLenMean = mean(lengths)
	s.SupportingFactsP50 = percentile(factCounts, 50)
	return s
}

func collectChallenger(runDir string) ChallengerStats {
	var s ChallengerStats
	paths, _ := filepath.Glob(filepath.Join(runfs.ChallengerDir(runDir), "challenge-*.json"))
	if len(paths) == 0 {
		return s
	}
	s.Present = true
	s.ChallengeCount = len(paths)
	nonRubber := 0
	var counterArgs []int
	var questions []int
	for _, p := range paths {
		var c artifacts.Challenge
		if err := runfs.ReadJSON(p, &c); err != nil {
			continue
		}
		counterArgs = append(counterArgs, len(c.CounterArguments))
		questions = append(questions, len(c.RemainingQuestions))
		// "rubber-stamp" = no counter arguments AND exploitability is
		// something like "agreed"/"likely". Non-rubber-stamp means
		// the challenger actually pushed back.
		if len(c.CounterArguments) > 0 || strings.EqualFold(c.ReviewerStance, "skeptical") {
			nonRubber++
		}
	}
	s.NonRubberStampRate = ratio(nonRubber, len(paths))
	s.CounterArgsP50 = percentile(counterArgs, 50)
	s.RemainingQuestionsP50 = percentile(questions, 50)
	return s
}

func collectVerifier(runDir string) VerifierStats {
	var s VerifierStats
	s.StatusDistribution = map[string]int{}
	paths, _ := filepath.Glob(filepath.Join(runfs.VerifierDir(runDir), "verify-*.json"))
	if len(paths) == 0 {
		return s
	}
	s.Present = true
	s.MemoCount = len(paths)
	corroborated := 0
	var facts []int
	var contradictions []int
	for _, p := range paths {
		var m artifacts.VerificationMemo
		if err := runfs.ReadJSON(p, &m); err != nil {
			continue
		}
		s.StatusDistribution[m.Status]++
		if m.Status == "corroborated" {
			corroborated++
		}
		facts = append(facts, len(m.ConfirmedFacts))
		contradictions = append(contradictions, len(m.Contradictions))
	}
	s.CorroborationRate = ratio(corroborated, len(paths))
	s.ConfirmedFactsP50 = percentile(facts, 50)
	s.ContradictionsP50 = percentile(contradictions, 50)
	return s
}

func collectArbiter(runDir string, verifierCount int) ArbiterStats {
	var s ArbiterStats
	s.StatusDistribution = map[string]int{}
	s.ConfidenceDistribution = map[string]int{}
	s.SeverityDistribution = map[string]int{}

	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err != nil {
		return s
	}
	s.Present = true
	s.FindingCount = len(findings.Findings)
	for _, f := range findings.Findings {
		s.StatusDistribution[f.Status]++
		s.ConfidenceDistribution[f.Confidence]++
		s.SeverityDistribution[f.Severity]++
	}

	// packet word count
	packetPaths, _ := filepath.Glob(filepath.Join(runfs.ArbiterPacketsDir(runDir), "*.md"))
	var wc []int
	for _, p := range packetPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		wc = append(wc, len(strings.Fields(string(data))))
	}
	s.PacketWordcountP50 = percentile(wc, 50)

	// agreement rate = fraction of findings whose status matches the
	// corresponding verifier memo, matched by slice_id == case_id.
	// Alphabetical / positional matching was tempting but fragile
	// when finding IDs mix categories (e.g. attestation:001 vs
	// key_management:002 sort differently than verify-001/002).
	if verifierCount > 0 && len(findings.Findings) > 0 {
		memoByCase := map[string]string{}
		memoPaths, _ := filepath.Glob(filepath.Join(runfs.VerifierDir(runDir), "verify-*.json"))
		for _, p := range memoPaths {
			var m artifacts.VerificationMemo
			if err := runfs.ReadJSON(p, &m); err != nil {
				continue
			}
			if m.CaseID != "" {
				memoByCase[m.CaseID] = m.Status
			}
		}
		agree := 0
		matched := 0
		for _, f := range findings.Findings {
			verifierStatus, ok := memoByCase[f.SliceID]
			if !ok {
				continue
			}
			matched++
			if verifierStatusMatches(verifierStatus, f.Status) {
				agree++
			}
		}
		s.VerifierAgreementRate = ratio(agree, matched)
	}
	return s
}

// verifierStatusMatches maps verifier statuses to arbiter statuses
// loosely so that "corroborated" in verifier aligns with "confirmed"
// or "corroborated" in arbiter.
func verifierStatusMatches(verifier, arbiter string) bool {
	v := strings.ToLower(strings.TrimSpace(verifier))
	a := strings.ToLower(strings.TrimSpace(arbiter))
	if v == a {
		return true
	}
	if v == "corroborated" && (a == "confirmed" || a == "needs_review") {
		return true
	}
	if v == "contested" && a == "needs_review" {
		return true
	}
	return false
}

func computeOverall(rs *RunStats) OverallStats {
	o := OverallStats{
		Dropoff: Dropoff{
			Candidates:   rs.Planner.CandidateCount,
			Cases:        rs.Cases.CaseCount,
			Hypotheses:   rs.Expert.HypothesisCount,
			Challenges:   rs.Challenger.ChallengeCount,
			Verifies:     rs.Verifier.MemoCount,
			Findings:     rs.Arbiter.FindingCount,
			Corroborated: rs.Verifier.StatusDistribution["corroborated"],
		},
	}
	if rs.Planner.CandidateCount > 0 {
		o.PipelineYield = ratio(o.Dropoff.Corroborated, rs.Planner.CandidateCount)
	}
	if o.Dropoff.Corroborated > 0 {
		o.CostPerCorroborated = rs.Planner.TokensUsed / o.Dropoff.Corroborated
	}
	return o
}

// Helpers -------------------------------------------------------------

func ratio(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom)
}

func percentile(values []int, p int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	idx := (p * (len(sorted) - 1)) / 100
	return sorted[idx]
}

func mean(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}
