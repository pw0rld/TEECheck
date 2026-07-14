// Package solver maps CodeQL evidence and accepted suppressors to a single TWE
// verdict status. It is the deterministic judgment layer (M5): it never calls
// an LLM and never invents facts — it only reads the evidence the fact engine
// produced and the suppressor signals detected, then applies fixed rules. This
// is what turns a CodeQL hit into an audit conclusion.
package solver

// Status is the solver's verdict vocabulary. Exactly one is emitted per site.
// The ordering of the constants reflects descending strength of an asserted
// issue: confirmed is the only closed-world "this is a violation" verdict.
type Status string

const (
	// Confirmed: the obligation is missing, the evidence is fully modeled, and
	// no accepted suppressor applies. The only closed-world violation verdict.
	Confirmed Status = "confirmed"
	// ViolatedCandidate: a violation is likely, but one relevant layer is not
	// modeled, so certainty is withheld.
	ViolatedCandidate Status = "violated_candidate"
	// Delegated: another verifier, wrapper, contract, or lower layer enforces
	// the obligation.
	Delegated Status = "delegated"
	// GuardedElsewhere: the obligation is satisfied through an accepted
	// alternative relation (including "the violation query found nothing").
	GuardedElsewhere Status = "guarded_elsewhere"
	// ConfigurationDependent: a weak path exists, but whether it reaches
	// production authority depends on configuration that is unknown.
	ConfigurationDependent Status = "configuration_dependent"
	// TestOnly: the path is test, mock, localnet, or example-only.
	TestOnly Status = "test_only"
	// OutOfScope: no matching TWE, or no TEE trust boundary.
	OutOfScope Status = "out_of_scope"
	// Unresolved: the build, Binder, query, or evidence is incomplete, so no
	// verdict can be reached.
	Unresolved Status = "unresolved"
)

// Vocabulary is the closed set of statuses, for validation and reporting.
var Vocabulary = map[Status]bool{
	Confirmed: true, ViolatedCandidate: true, Delegated: true,
	GuardedElsewhere: true, ConfigurationDependent: true, TestOnly: true,
	OutOfScope: true, Unresolved: true,
}

// IsReportedIssue reports whether a status represents something a reviewer
// should look at as a potential problem (as opposed to a cleared or
// non-applicable site). Used by findings emission and benchmark scoring.
func (s Status) IsReportedIssue() bool {
	switch s {
	case Confirmed, ViolatedCandidate, ConfigurationDependent:
		return true
	default:
		return false
	}
}
