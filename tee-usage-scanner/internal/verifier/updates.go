package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// invariantUpdateLogPath is the append-only log the Verifier writes
// proposed invariant-status changes to. §3.5 forbids overwriting the
// original `proposed` ProjectInvariant artifact — the Verifier
// package never calls runfs.WriteJSON against
// runfs.ProjectInvariantsPath; this log is the ONLY place it records
// a status opinion, and it is opened O_APPEND every time.
func invariantUpdateLogPath(runDir string) string {
	return filepath.Join(runfs.VerifierDir(runDir), "invariant_status_updates.jsonl")
}

// invariantUpdateLogEntry adds the case_id so a reader of the shared,
// whole-run log can tell which case's dispute produced which update
// without cross-referencing verify-NNN.json files.
type invariantUpdateLogEntry struct {
	CaseID string `json:"case_id"`
	artifacts.InvariantStatusUpdate
}

// appendInvariantUpdates appends one JSON line per update to the
// run's invariant_status_updates.jsonl. Opened with O_APPEND so a
// concurrent or repeated call can never truncate earlier entries —
// the append-not-overwrite guarantee is enforced by the open flags,
// not just by convention.
func appendInvariantUpdates(runDir, caseID string, updates []artifacts.InvariantStatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	path := invariantUpdateLogPath(runDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, u := range updates {
		entry := invariantUpdateLogEntry{CaseID: caseID, InvariantStatusUpdate: u}
		if err := enc.Encode(entry); err != nil {
			return err
		}
	}
	return nil
}

// computeInvariantUpdates (§7.8: "更新invariant verification status
// 但保留原始 proposed artifact") maps the Verifier's dispute-resolution
// status onto the status vocabulary
// schemas/project-invariant.v1.json defines. Only invariants whose
// status would actually change produce an update — an invariant the
// Verifier didn't move the needle on gets no entry, so the log stays
// a record of actual decisions rather than a restatement of every
// invariant on every case.
func computeInvariantUpdates(invs []artifacts.ProjectInvariant, memoStatus string) []artifacts.InvariantStatusUpdate {
	var updates []artifacts.InvariantStatusUpdate
	for _, inv := range invs {
		var newStatus, reason string
		switch memoStatus {
		case "corroborated":
			newStatus = "violated_candidate"
			reason = "verifier corroborated the disputed claim that this invariant's obligation is unmet"
		case "contested":
			newStatus = "unresolved"
			reason = "verifier found conflicting evidence for this invariant; dispute not resolved"
		default: // "inconclusive" and any unrecognized value
			newStatus = "unresolved"
			reason = "verifier could not reach a conclusion for this invariant (inconclusive)"
		}
		if newStatus == inv.Status {
			continue
		}
		updates = append(updates, artifacts.InvariantStatusUpdate{
			InvariantID:    inv.InvariantID,
			PreviousStatus: inv.Status,
			NewStatus:      newStatus,
			Reason:         reason,
		})
	}
	return updates
}

// computeEvidenceDistinctions (§7.8: "区分「未找到」与「证明不存在」")
// looks at the ToolFacts a case referenced and classifies each
// zero-locations fact as either a genuine proof of absence (the
// query ran to completion — status ok, not truncated, no coverage
// gaps — and still found nothing) or a merely-inconclusive search
// (truncated, incomplete, or reported coverage gaps). It also flags
// the case where the ONLY search performed was a grep-based static
// check: grep can never prove absence, only report "not found here".
func computeEvidenceDistinctions(caseCtx caseContext, ranStaticSearch bool, scFindings []staticcheck.CheckFinding) []artifacts.EvidenceDistinctionNote {
	var notes []artifacts.EvidenceDistinctionNote
	for _, f := range caseCtx.toolFacts {
		if len(f.Locations) > 0 {
			// Found something — this is a presence claim, not an
			// absence one; nothing to distinguish here.
			continue
		}
		claim := fmt.Sprintf("tool fact %s (%s/%s) reported no matching locations", f.FactID, f.Tool, f.Operation)
		exhaustive := f.Status == "ok" && !f.Truncated && len(f.CoverageGaps) == 0
		if exhaustive {
			notes = append(notes, artifacts.EvidenceDistinctionNote{
				Claim: claim, Outcome: artifacts.EvidenceProvenAbsent,
				Note: "tool query completed (status ok, not truncated, no coverage gaps) and found zero matches",
			})
			continue
		}
		reason := "tool query did not complete exhaustively"
		switch {
		case f.Status != "ok":
			reason = fmt.Sprintf("tool status=%q, not a completed ok result", f.Status)
		case f.Truncated:
			reason = "tool result was truncated"
		case len(f.CoverageGaps) > 0:
			reason = "tool reported coverage gaps: " + strings.Join(f.CoverageGaps, "; ")
		}
		notes = append(notes, artifacts.EvidenceDistinctionNote{Claim: claim, Outcome: artifacts.EvidenceNotFound, Note: reason})
	}

	if ranStaticSearch && len(scFindings) == 0 && len(caseCtx.toolFacts) == 0 {
		notes = append(notes, artifacts.EvidenceDistinctionNote{
			Claim:   "grep/static keyword search for this case's expected obligations",
			Outcome: artifacts.EvidenceNotFound,
			Note:    "a keyword search can only report 'not found here' — it cannot prove the property is absent from the codebase",
		})
	}
	return notes
}

// disputeDrivenKeywords (§7.8: "将双方争议转换成具体工具问题") widens the
// static-check search beyond the Case Pack's own
// expected_obligations/target_symbols to include the case's
// RequiredEvidence, the relevant invariants' RequiredProperties /
// ExpectedDefenses, and whatever the Challenger's SuggestedChecks
// named — so the tool call is actually aimed at the specific dispute
// rather than a generic keyword list.
func disputeDrivenKeywords(pack artifacts.CasePack, challenge artifacts.Challenge, invs []artifacts.ProjectInvariant) []string {
	kws := append([]string{}, pack.ExpectedObligations...)
	kws = append(kws, pack.TargetSymbols...)
	kws = append(kws, pack.RequiredEvidence...)
	for _, inv := range invs {
		kws = append(kws, inv.RequiredProperties...)
		kws = append(kws, inv.ExpectedDefenses...)
	}
	kws = append(kws, challenge.SuggestedChecks...)
	return uniqStrings(kws)
}

// renderArchitectureChecks renders a short "what did the Verifier
// consult" note per architecture element/relation in the case's
// slice, naming its EvidenceState so a reader can see when the
// Verifier's judgment leaned on an inferred/documented/unknown
// statement rather than an observed one (§7.8: "验证争议所依赖的
// architecture statement").
func renderArchitectureChecks(model *artifacts.ArchitectureModel) []string {
	if model == nil {
		return nil
	}
	var out []string
	note := func(id, kind string, state artifacts.EvidenceState) {
		if state != artifacts.EvidenceObserved {
			out = append(out, fmt.Sprintf("%s:%s is %s, not observed — treated as unconfirmed background, not proof", kind, id, state))
		}
	}
	for _, e := range model.Parties {
		note(e.ID, "party", e.State)
	}
	for _, e := range model.Components {
		note(e.ID, "component", e.State)
	}
	for _, e := range model.Roles {
		note(e.ID, "role", e.State)
	}
	for _, e := range model.Assets {
		note(e.ID, "asset", e.State)
	}
	for _, e := range model.TrustZones {
		note(e.ID, "trust_zone", e.State)
	}
	for _, e := range model.Entrypoints {
		note(e.ID, "entrypoint", e.State)
	}
	for _, r := range model.Boundaries {
		note(r.ID, "boundary", r.State)
	}
	for _, r := range model.DataFlows {
		note(r.ID, "data_flow", r.State)
	}
	for _, r := range model.StateLifecycles {
		note(r.ID, "state_lifecycle", r.State)
	}
	return out
}

// renderInvariantChecks names, per invariant in the case's slice, the
// verification-plan steps the Verifier should have run against — a
// short pointer to what "verify this" means for that invariant.
func renderInvariantChecks(invs []artifacts.ProjectInvariant) []string {
	var out []string
	for _, inv := range invs {
		if len(inv.VerificationPlan) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s [%s]: %s", inv.InvariantID, inv.Status, strings.Join(inv.VerificationPlan, "; ")))
	}
	return out
}

// firstNonEmptyStr returns the first non-blank value, or the last
// argument (the intended fallback) if every candidate is blank.
func firstNonEmptyStr(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func uniqStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
