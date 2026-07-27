package architecture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/symbolcheck"
)

// StateAdjustment records one place ValidateAndDowngrade (or
// NormalizeStates) changed a statement's declared state — either because
// its citation failed to check out, or because the model declared a state
// outside the observed/inferred/documented/unknown enum. §22 requires the
// downgrade to be "recorded, not just applied, so a reader can see it
// happened": the model persists this both structurally (returned here, for
// callers/tests/the dossier) and textually (appended to the element's own
// Description field — see appendAdjustmentNote — so a reader who only has
// the final architecture.v1.json can still see it happened).
type StateAdjustment struct {
	Bucket    string                  `json:"bucket"`
	ElementID string                  `json:"element_id"`
	FromState artifacts.EvidenceState `json:"from_state"`
	ToState   artifacts.EvidenceState `json:"to_state"`
	Reason    string                  `json:"reason"`
}

var validStates = map[artifacts.EvidenceState]bool{
	artifacts.EvidenceObserved:   true,
	artifacts.EvidenceInferred:   true,
	artifacts.EvidenceDocumented: true,
	artifacts.EvidenceUnknown:    true,
}

// NormalizeStates defaults any element/relation whose declared state is not
// one of the four canonical values (missing, misspelled, or invented by the
// model) to unknown. This is the concrete mechanism behind the §22
// constraint "unknown must survive — the agent may not guess to complete
// its JSON": an out-of-enum or empty state is never coerced toward a
// stronger value (e.g. defaulting to "inferred" as a guess), only toward
// the weakest, most conservative one.
func NormalizeStates(model artifacts.ArchitectureModel) (artifacts.ArchitectureModel, []StateAdjustment) {
	var adjustments []StateAdjustment
	normalizeElements := func(bucket string, elems []artifacts.ArchitectureElement) []artifacts.ArchitectureElement {
		for i := range elems {
			if !validStates[elems[i].State] {
				from := elems[i].State
				adjustments = append(adjustments, StateAdjustment{
					Bucket: bucket, ElementID: elems[i].ID,
					FromState: from, ToState: artifacts.EvidenceUnknown,
					Reason: fmt.Sprintf("declared state %q is not observed|inferred|documented|unknown", string(from)),
				})
				elems[i].State = artifacts.EvidenceUnknown
				elems[i].Description = appendAdjustmentNote(elems[i].Description, from, artifacts.EvidenceUnknown, adjustments[len(adjustments)-1].Reason)
			}
		}
		return elems
	}
	normalizeRelations := func(bucket string, rels []artifacts.ArchitectureRelation) []artifacts.ArchitectureRelation {
		for i := range rels {
			if !validStates[rels[i].State] {
				from := rels[i].State
				adjustments = append(adjustments, StateAdjustment{
					Bucket: bucket, ElementID: rels[i].ID,
					FromState: from, ToState: artifacts.EvidenceUnknown,
					Reason: fmt.Sprintf("declared state %q is not observed|inferred|documented|unknown", string(from)),
				})
				rels[i].State = artifacts.EvidenceUnknown
				rels[i].Description = appendAdjustmentNote(rels[i].Description, from, artifacts.EvidenceUnknown, adjustments[len(adjustments)-1].Reason)
			}
		}
		return rels
	}

	model.Parties = normalizeElements("parties", model.Parties)
	model.Components = normalizeElements("components", model.Components)
	model.Roles = normalizeElements("roles", model.Roles)
	model.Assets = normalizeElements("assets", model.Assets)
	model.TrustZones = normalizeElements("trust_zones", model.TrustZones)
	model.Entrypoints = normalizeElements("entrypoints", model.Entrypoints)
	model.TrustAssumptions = normalizeElements("trust_assumptions", model.TrustAssumptions)
	model.DeploymentAssumptions = normalizeElements("deployment_assumptions", model.DeploymentAssumptions)
	model.Unknowns = normalizeElements("unknowns", model.Unknowns)
	model.Boundaries = normalizeRelations("boundaries", model.Boundaries)
	model.DataFlows = normalizeRelations("data_flows", model.DataFlows)
	model.StateLifecycles = normalizeRelations("state_lifecycles", model.StateLifecycles)
	return model, adjustments
}

// ValidateAndDowngrade is the citation validator §22 calls out as its own
// deliverable — see the package doc comment for the full design rationale.
// It re-derives every observed/documented statement's citation against
// repoRoot and downgrades any statement whose citation does not check out.
// inferred/unknown statements are untouched: they never carried a
// citation-backed claim in the first place, so there is nothing to
// re-validate (and, per §22, nothing here ever promotes them upward either
// — this function only ever lowers a state, never raises one).
func ValidateAndDowngrade(model artifacts.ArchitectureModel, repoRoot string) (artifacts.ArchitectureModel, []StateAdjustment) {
	var adjustments []StateAdjustment

	validateElements := func(bucket string, elems []artifacts.ArchitectureElement) []artifacts.ArchitectureElement {
		for i := range elems {
			el := &elems[i]
			if el.State != artifacts.EvidenceObserved && el.State != artifacts.EvidenceDocumented {
				continue
			}
			symbol := el.Name
			reason, ok := checkEvidence(el.Evidence, symbol, repoRoot)
			if ok {
				continue
			}
			from := el.State
			to := downgradeTarget(len(el.Dependencies) > 0)
			adjustments = append(adjustments, StateAdjustment{
				Bucket: bucket, ElementID: el.ID, FromState: from, ToState: to, Reason: reason,
			})
			el.State = to
			el.Description = appendAdjustmentNote(el.Description, from, to, reason)
		}
		return elems
	}
	validateRelations := func(bucket string, rels []artifacts.ArchitectureRelation) []artifacts.ArchitectureRelation {
		for i := range rels {
			rel := &rels[i]
			if rel.State != artifacts.EvidenceObserved && rel.State != artifacts.EvidenceDocumented {
				continue
			}
			// Relations have no Name-shaped field to fall back on as an
			// expected symbol (From/To are internal element IDs, not
			// source tokens) — see the package doc comment. Symbol
			// containment is checked only when the relation's own
			// evidence.note supplies one; existence+range is always
			// checked either way.
			reason, ok := checkEvidence(rel.Evidence, "", repoRoot)
			if ok {
				continue
			}
			from := rel.State
			to := downgradeTarget(len(rel.Dependencies) > 0)
			adjustments = append(adjustments, StateAdjustment{
				Bucket: bucket, ElementID: rel.ID, FromState: from, ToState: to, Reason: reason,
			})
			rel.State = to
			rel.Description = appendAdjustmentNote(rel.Description, from, to, reason)
		}
		return rels
	}

	model.Parties = validateElements("parties", model.Parties)
	model.Components = validateElements("components", model.Components)
	model.Roles = validateElements("roles", model.Roles)
	model.Assets = validateElements("assets", model.Assets)
	model.TrustZones = validateElements("trust_zones", model.TrustZones)
	model.Entrypoints = validateElements("entrypoints", model.Entrypoints)
	model.TrustAssumptions = validateElements("trust_assumptions", model.TrustAssumptions)
	model.DeploymentAssumptions = validateElements("deployment_assumptions", model.DeploymentAssumptions)
	// Unknowns are exempt: an unknown statement makes no citation-backed
	// claim to check in the first place.
	model.Boundaries = validateRelations("boundaries", model.Boundaries)
	model.DataFlows = validateRelations("data_flows", model.DataFlows)
	model.StateLifecycles = validateRelations("state_lifecycles", model.StateLifecycles)
	return model, adjustments
}

// downgradeTarget picks between the two downgrade targets §22 names
// ("降级为 inferred 或 unknown"): a statement that still names dependency
// facts has grounds to stand as inferred; one with nothing left to point at
// has nothing to be inferred from and drops all the way to unknown.
func downgradeTarget(hasDependencies bool) artifacts.EvidenceState {
	if hasDependencies {
		return artifacts.EvidenceInferred
	}
	return artifacts.EvidenceUnknown
}

// checkEvidence is the actual per-statement check: does every evidence
// entry resolve, and — for line-anchored citations — does the cited region
// actually contain the declared symbol? Strict "any failure fails the
// whole statement" semantics, matching citations.ValidateFacts's existing
// policy (a fact backed by 5 citations where 1 drifted is reported as
// stale, not "80% valid") — a statement is only as trustworthy as its
// weakest citation.
//
// expectedSymbol is the fallback symbol to check for when an evidence entry
// does not supply its own via Note (see the package doc comment on why Note
// is the primary carrier and Name/expectedSymbol is the fallback). Pass ""
// for relations, which have no Name-shaped fallback.
//
// Evidence with StartLine < 1 is treated as a path-only claim ("this file
// exists"), not a byte-range claim, and is checked for existence only —
// this is how manifest evidence ("this EDL/Gramine/TA manifest file exists
// at this path") validates on its bare existence. Evidence with an
// ArtifactRef and no File points at
// a persisted tool result, not source bytes; that is PR-05's fact-layer
// integrity to check, not this validator's, so it is accepted here without
// a file check.
// fileIsSufficientEvidence reports whether a file-only citation (no line
// range) can back an observed/documented statement on the strength of the
// file existing alone. True for manifest/config/doc-style evidence, where the
// statement's Name is a human description rather than a token that must appear
// in the file. False for source evidence, where a file-only citation with no
// verifiable symbol is exactly the hole that lets a fabricated "observed"
// stand — see checkEvidence.
func fileIsSufficientEvidence(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "manifest", "config", "configuration", "deployment",
		"doc", "documentation", "code_or_config":
		return true
	}
	return false
}

func checkEvidence(evidence []artifacts.EvidenceReference, expectedSymbol, repoRoot string) (reason string, ok bool) {
	if len(evidence) == 0 {
		return "no evidence attached to an observed/documented statement", false
	}
	for _, ref := range evidence {
		if ref.File == "" {
			if ref.ArtifactRef != "" {
				continue
			}
			return "evidence has neither file nor artifact_ref", false
		}
		if ref.StartLine < 1 {
			if _, err := os.Stat(resolveRepoPath(repoRoot, ref.File)); err != nil {
				return fmt.Sprintf("cited file does not exist: %s (%v)", ref.File, err), false
			}
			// For manifest/doc-style evidence the file's mere existence is
			// the evidence — the statement's Name is a description ("SGX
			// enclave configuration"), not a token to find inside the file.
			if fileIsSufficientEvidence(ref.Kind) {
				continue
			}
			// For source evidence, file existence proves nothing about
			// content. Accepting it here would let "observed component Foo
			// in X.c" stand when Foo is nowhere in X.c, just by omitting the
			// line number. Require the declared symbol to appear somewhere
			// in the file.
			symbol := strings.TrimSpace(ref.Note)
			if symbol == "" {
				symbol = expectedSymbol
			}
			if symbol == "" {
				return fmt.Sprintf("source citation %s has no line range and no symbol to verify", ref.File), false
			}
			ok, err := symbolcheck.FileContainsSymbol(repoRoot, ref.File, symbol)
			if err != nil {
				return fmt.Sprintf("could not read cited file %s: %v", ref.File, err), false
			}
			if !ok {
				return fmt.Sprintf("cited file %s does not contain declared symbol %q", ref.File, symbol), false
			}
			continue
		}
		cited := ref.CitedBytes()
		resolved, err := citations.Resolve(cited, repoRoot)
		if err != nil {
			return fmt.Sprintf("citation did not resolve: %v", err), false
		}
		symbol := strings.TrimSpace(ref.Note)
		if symbol == "" {
			symbol = expectedSymbol
		}
		if symbol == "" {
			continue
		}
		contains, err := citedRegionContains(repoRoot, resolved, symbol)
		if err != nil {
			return fmt.Sprintf("could not read cited region: %v", err), false
		}
		if !contains {
			return fmt.Sprintf("cited region %s:%d-%d does not contain declared symbol %q", ref.File, ref.StartLine, ref.EndLine, symbol), false
		}
	}
	return "", true
}

// citedRegionContains re-reads the already-Resolve'd citation's exact byte
// range and checks for symbol as a case-insensitive substring. This reads
// the file a second time (Resolve only returns a hash, not the bytes
// themselves) rather than adding a bytes-returning variant to the citations
// package's public surface — the citations package's job stops at proving a
// byte range exists and hashes consistently; "does this specific content
// contain X" is a project-understanding-layer question, not a general
// citation-contract one.
func citedRegionContains(repoRoot string, c citations.CitedBytes, symbol string) (bool, error) {
	body, err := os.ReadFile(resolveRepoPath(repoRoot, c.File))
	if err != nil {
		return false, err
	}
	if c.StartByte < 0 || c.EndByte > int64(len(body)) || c.StartByte > c.EndByte {
		return false, fmt.Errorf("resolved byte range out of bounds for %s", c.File)
	}
	region := body[c.StartByte:c.EndByte]
	return strings.Contains(strings.ToLower(string(region)), strings.ToLower(symbol)), nil
}

func resolveRepoPath(repoRoot, file string) string {
	if filepath.IsAbs(file) || repoRoot == "" {
		return file
	}
	return filepath.Join(repoRoot, file)
}

// appendAdjustmentNote makes a downgrade visible in the persisted artifact
// itself (Description is a free-text, schema-legal field), not only in the
// StateAdjustment slice returned to the caller — see StateAdjustment's doc
// comment for why both are needed.
func appendAdjustmentNote(description string, from, to artifacts.EvidenceState, reason string) string {
	note := fmt.Sprintf("[citation check: downgraded %s -> %s: %s]", from, to, reason)
	if description == "" {
		return note
	}
	return description + " " + note
}
