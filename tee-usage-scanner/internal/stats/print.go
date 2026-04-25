package stats

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Print writes a human-readable summary of RunStats to w. The format
// is meant for eyeballing in a terminal; for machine consumption read
// the JSON produced by Collect directly.
func Print(w io.Writer, rs *RunStats) {
	fmt.Fprintf(w, "=== TEECheck run stats — %s ===\n", rs.RunID)
	fmt.Fprintf(w, "Run dir: %s\n", rs.RunDir)
	if rs.Source != "" {
		fmt.Fprintf(w, "Source:  %s\n", rs.Source)
	}
	fmt.Fprintln(w)

	// Planner
	if rs.Planner.Present {
		p := rs.Planner
		fmt.Fprintf(w, "Planner")
		if p.Source != "" {
			fmt.Fprintf(w, " [source=%s]", p.Source)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  candidates=%d  termination=%s  rounds=%d/%d  diversity=%d\n",
			p.CandidateCount, p.TerminationReason, p.RoundsUsed, p.RoundsBudget, p.DiversityIndex)
		fmt.Fprintf(w, "  path_validity=%.2f  symbol_validity=%.2f\n", p.PathValidityRate, p.SymbolValidityRate)
		fmt.Fprintf(w, "  tokens_used=%d  wall_clock=%dms\n", p.TokensUsed, p.WallClockMs)
		fmt.Fprintf(w, "  action_mix=%s\n", formatMapInt(p.ActionMix))
		if len(p.TokensByRound) > 0 {
			fmt.Fprintf(w, "  tokens_by_round=%v\n", p.TokensByRound)
		}
		if len(p.HallucinatedPaths) > 0 {
			fmt.Fprintf(w, "  ⚠ hallucinated_paths: %v\n", p.HallucinatedPaths)
		}
		if len(p.HallucinatedSymbols) > 0 {
			fmt.Fprintf(w, "  ⚠ hallucinated_symbols: %v\n", p.HallucinatedSymbols)
		}
	} else {
		fmt.Fprintf(w, "Planner: (not present — heuristic mode or missing bundle)\n")
	}

	// Cases
	if rs.Cases.Present {
		c := rs.Cases
		fmt.Fprintf(w, "\nCases\n")
		fmt.Fprintf(w, "  case_count=%d  symbol_coverage=%.2f  obligations_attached=%d\n",
			c.CaseCount, c.SymbolCoverageRate, c.ObligationsAttached)
		fmt.Fprintf(w, "  snippet_lines p50=%d mean=%d\n", c.SnippetLineTotalP50, c.SnippetLineTotalMean)
	}

	// Expert
	if rs.Expert.Present {
		e := rs.Expert
		fmt.Fprintf(w, "\nExpert\n")
		fmt.Fprintf(w, "  hypotheses=%d  citation_rate=%.2f  citation_validity=%.2f  words_p50=%d  facts_p50=%d\n",
			e.HypothesisCount, e.CitationRate, e.CitationValidityRate, e.HypothesisLenP50, e.SupportingFactsP50)
	}

	// Challenger
	if rs.Challenger.Present {
		c := rs.Challenger
		fmt.Fprintf(w, "\nChallenger\n")
		fmt.Fprintf(w, "  challenges=%d  non_rubber_stamp=%.2f  counter_args_p50=%d\n",
			c.ChallengeCount, c.NonRubberStampRate, c.CounterArgsP50)
	}

	// Verifier
	if rs.Verifier.Present {
		v := rs.Verifier
		fmt.Fprintf(w, "\nVerifier\n")
		fmt.Fprintf(w, "  memos=%d  corroboration_rate=%.2f\n", v.MemoCount, v.CorroborationRate)
		fmt.Fprintf(w, "  status_distribution=%s\n", formatMapInt(v.StatusDistribution))
		fmt.Fprintf(w, "  confirmed_facts_p50=%d  contradictions_p50=%d\n", v.ConfirmedFactsP50, v.ContradictionsP50)
	}

	// Arbiter
	if rs.Arbiter.Present {
		a := rs.Arbiter
		fmt.Fprintf(w, "\nArbiter\n")
		fmt.Fprintf(w, "  findings=%d  verifier_agreement=%.2f  packet_words_p50=%d\n",
			a.FindingCount, a.VerifierAgreementRate, a.PacketWordcountP50)
		fmt.Fprintf(w, "  status=%s\n", formatMapInt(a.StatusDistribution))
		fmt.Fprintf(w, "  severity=%s  confidence=%s\n",
			formatMapInt(a.SeverityDistribution), formatMapInt(a.ConfidenceDistribution))
	}

	// Overall
	o := rs.Overall
	fmt.Fprintf(w, "\nOverall\n")
	fmt.Fprintf(w, "  pipeline_yield=%.2f  cost_per_corroborated=%d tokens\n",
		o.PipelineYield, o.CostPerCorroborated)
	fmt.Fprintf(w, "  dropoff: candidates=%d cases=%d hypotheses=%d challenges=%d verifies=%d findings=%d corroborated=%d\n",
		o.Dropoff.Candidates, o.Dropoff.Cases, o.Dropoff.Hypotheses,
		o.Dropoff.Challenges, o.Dropoff.Verifies, o.Dropoff.Findings, o.Dropoff.Corroborated)
}

func formatMapInt(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return "{" + strings.Join(parts, " ") + "}"
}
