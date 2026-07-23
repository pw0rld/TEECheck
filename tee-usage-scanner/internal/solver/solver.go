package solver

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// SolveInput is everything the solver needs to judge one candidate site. Every
// field is a fact produced upstream (fact engine, binder, planner) — the solver
// adds no information of its own.
type SolveInput struct {
	Entry  twe.Entry
	SiteID string

	// BuildOK and QueryRan report pipeline completeness. If either is false
	// the evidence is incomplete and the verdict is Unresolved.
	BuildOK  bool
	QueryRan bool

	// ViolationResults are the SARIF findings the TWE's violation query
	// produced for this site. Empty means the obligation is satisfied.
	ViolationResults []codeql.Result

	// Modeled is true when every layer relevant to the obligation was
	// modeled. A violation on an incompletely modeled site is a candidate,
	// not a confirmation.
	Modeled bool

	// Suppressors are the suppressor signals detected at this site (e.g.
	// "test_or_dev_only"). Only those also listed in the TWE's
	// accepted_suppressors can downgrade the verdict.
	Suppressors []string
}

// Result is the solver verdict for one site.
type Result struct {
	TWEID             string          `json:"twe_id"`
	SiteID            string          `json:"site_id"`
	Status            Status          `json:"status"`
	Reason            string          `json:"reason"`
	AppliedSuppressor string          `json:"applied_suppressor,omitempty"`
	Evidence          []codeql.Result `json:"evidence,omitempty"`
}

// Solve applies the fixed status rules. The order matters: completeness gates
// first (no evidence → no verdict), then the presence of a violation, then
// suppressor downgrades, and only a fully-modeled unsuppressed violation
// reaches Confirmed.
func Solve(in SolveInput) Result {
	res := Result{TWEID: in.Entry.ID, SiteID: in.SiteID, Evidence: in.ViolationResults}

	if in.Entry.ID == "" {
		res.Status = OutOfScope
		res.Reason = "no matching TWE for this site"
		return res
	}
	if !in.BuildOK || !in.QueryRan {
		res.Status = Unresolved
		res.Reason = "incomplete evidence: build or query did not complete"
		return res
	}
	if len(in.ViolationResults) == 0 {
		res.Status = GuardedElsewhere
		res.Reason = "violation query produced no evidence; obligation satisfied"
		return res
	}

	// A violation is present. An accepted suppressor downgrades it. The TWE's
	// accepted_suppressors list is the author-controlled priority order.
	if name, ok := firstAcceptedSuppressor(in.Entry.AcceptedSuppressors, in.Suppressors); ok {
		res.Status = classifySuppressor(name)
		res.AppliedSuppressor = name
		res.Reason = fmt.Sprintf("violation present but downgraded by accepted suppressor %q", name)
		return res
	}

	if !in.Modeled {
		res.Status = ViolatedCandidate
		res.Reason = "violation present but a relevant layer is not fully modeled"
		return res
	}

	res.Status = Confirmed
	res.Reason = "obligation missing, evidence modeled, no accepted suppressor applies"
	return res
}

// firstAcceptedSuppressor returns the first suppressor from the TWE's accepted
// list (author priority order) that was actually detected at the site.
func firstAcceptedSuppressor(accepted, detected []string) (string, bool) {
	present := make(map[string]bool, len(detected))
	for _, d := range detected {
		present[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for _, a := range accepted {
		if present[strings.ToLower(strings.TrimSpace(a))] {
			return a, true
		}
	}
	return "", false
}

// classifySuppressor maps a suppressor name to the verdict it implies. The
// mapping is by intent keyword so new suppressors following the naming
// conventions classify without a code change; anything unrecognised defaults to
// GuardedElsewhere (the obligation is met through an accepted relation).
func classifySuppressor(name string) Status {
	n := strings.ToLower(name)
	switch {
	case containsAny(n, "test", "dev", "mock", "example", "localnet"):
		return TestOnly
	case containsAny(n, "mode", "config", "feature", "production", "simulation", "debug"):
		return ConfigurationDependent
	case containsAny(n, "verifier", "wrapper", "delegat", "lower", "contract", "caller"):
		return Delegated
	default:
		return GuardedElsewhere
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
