package planner

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

const preScannedTaintMaxBytes = 12 << 10
const preScannedTaintHeading = "PRE-SCANNED TAINT CANDIDATES (deterministic CodeQL clues, not verdicts)"

// PreScannedTaint carries a run-local L2 query's immutable evidence and a
// bounded navigation preview. It does not credit any source read or prove an
// externally reachable flow, missing guard, vulnerability, or safe outcome.
type PreScannedTaint struct {
	FactRef       string   `json:"fact_ref,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	ContentSHA256 string   `json:"content_sha256,omitempty"`
	CoverageGaps  []string `json:"coverage_gaps,omitempty"`
}

// validatePreScannedTaint runs before completed-checkpoint reuse too. The
// frozen digest additionally binds a fact whose payload and self-digest were
// both replaced after the original run.
func validatePreScannedTaint(cfg RunConfig) (*PreScannedTaint, *artifacts.ToolFact, error) {
	if cfg.PreScannedTaint == nil {
		return nil, nil, nil
	}
	context := *cfg.PreScannedTaint
	context.CoverageGaps = append([]string(nil), context.CoverageGaps...)
	if context.FactRef == "" {
		if strings.TrimSpace(context.Summary) != "" {
			return nil, nil, fmt.Errorf("pre-scanned taint summary has no immutable fact reference")
		}
		return &context, nil, nil
	}
	m, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return nil, nil, fmt.Errorf("pre-scanned taint manifest: %w", err)
	}
	if m.RunID != cfg.RunID || (cfg.Profile.RepoURL != "" && cfg.Profile.RepoURL != m.RepoURL) || (cfg.Profile.Commit != "" && cfg.Profile.Commit != m.Commit) {
		return nil, nil, fmt.Errorf("pre-scanned taint belongs to another run or source profile")
	}
	scope := m.Scope
	if scope.Hash == "" {
		scope = runfs.BuildScope(m.RepoURL, m.Commit, cfg.RepoRoot)
	}
	fact, err := contracts.LoadToolFact(context.FactRef, contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: cfg.RepoRoot, Scope: scope})
	if err != nil {
		return nil, nil, fmt.Errorf("pre-scanned taint evidence: %w", err)
	}
	if fact.Operation != artifacts.TaintPrescanOperation || fact.Status != "success" || fact.Scope == nil || fact.Scope.RepoURL != scope.RepoURL || fact.Scope.Commit != scope.Commit || fact.Scope.Hash != scope.Hash {
		return nil, nil, fmt.Errorf("pre-scanned taint requires a successful cpp.taint.prescan fact in this exact source scope")
	}
	if context.ContentSHA256 != "" && context.ContentSHA256 != fact.ContentSHA256 {
		return nil, nil, fmt.Errorf("pre-scanned taint immutable content digest changed")
	}
	context.ContentSHA256 = fact.ContentSHA256
	var identity struct {
		QueryVersion      string `json:"query_version"`
		QuerySHA256       string `json:"query_sha256"`
		TreeContentSHA256 string `json:"tree_content_sha256"`
	}
	if json.Unmarshal(fact.Result, &identity) != nil || identity.QueryVersion == "" {
		return nil, nil, fmt.Errorf("pre-scanned taint has no query/source identity")
	}
	for _, digest := range []string{identity.QuerySHA256, identity.TreeContentSHA256} {
		if decoded, err := hex.DecodeString(digest); err != nil || len(decoded) != 32 {
			return nil, nil, fmt.Errorf("pre-scanned taint has invalid query/source digest")
		}
	}
	tree, err := sourcehash.TreeExcluding(cfg.RepoRoot, []string{cfg.RunDir})
	if err != nil || tree != identity.TreeContentSHA256 {
		return nil, nil, fmt.Errorf("pre-scanned taint source contents differ from the current tree")
	}
	if !utf8.ValidString(context.Summary) {
		return nil, nil, fmt.Errorf("pre-scanned taint summary is not valid UTF-8")
	}
	return &context, &fact, nil
}

func seedPreScannedTaint(context *PreScannedTaint, fact *artifacts.ToolFact, observed *ObservationSet, executed *[]string) {
	if context == nil || fact == nil {
		return
	}
	*executed = unionStrings(*executed, []string{context.FactRef})
	observed.Record(context.FactRef, true)
	if fact.FactID != "" {
		observed.Record(fact.FactID, true)
	}
}

// Keep whole candidate paragraphs when bounding a preview; never cut a path
// halfway and present its prefix as though it were the complete witness.
func preScannedTaintBlock(context *PreScannedTaint) string {
	if context == nil || context.FactRef == "" || strings.TrimSpace(context.Summary) == "" {
		return ""
	}
	header := "=== " + preScannedTaintHeading + " ===\n"
	body := strings.TrimSpace(context.Summary)
	if strings.Contains(strings.SplitN(body, "\n", 2)[0], preScannedTaintHeading) {
		if len(body)+2 <= preScannedTaintMaxBytes {
			return body + "\n\n"
		}
		if len(context.Summary) <= preScannedTaintMaxBytes {
			return context.Summary
		}
		_, body, _ = strings.Cut(body, "\n")
	}
	var b strings.Builder
	b.WriteString(header)
	line := "fact_ref: " + context.FactRef + "\nStatic may-flow witnesses only. Read the source; zero paths do NOT prove safety.\n\n"
	if b.Len()+len(line) >= preScannedTaintMaxBytes {
		return ""
	}
	b.WriteString(line)
	const omitted = "\nAdditional preview content omitted; read the referenced immutable ToolFact for the complete witness set.\n"
	for _, paragraph := range strings.Split(body, "\n\n") {
		if paragraph == "" {
			continue
		}
		if b.Len()+len(paragraph)+2+len(omitted) > preScannedTaintMaxBytes {
			b.WriteString(omitted)
			break
		}
		b.WriteString(paragraph)
		b.WriteString("\n\n")
	}
	return b.String()
}

func prescanFactPath(cfg RunConfig) string {
	if cfg.PreScannedTaint == nil {
		return ""
	}
	ref := cfg.PreScannedTaint.FactRef
	if filepath.IsAbs(ref) {
		return filepath.Clean(ref)
	}
	root, err := filepath.Abs(cfg.RunDir)
	if err != nil {
		return ref
	}
	if abs, err := filepath.Abs(ref); err == nil {
		if rel, err := filepath.Rel(root, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return abs
		}
	}
	return filepath.Join(root, filepath.FromSlash(ref))
}

// A narrowly scoped lead may follow presented L2 evidence before broad MAP
// browsing finishes. Both endpoints must have appeared as actual source in a
// prior committed round, and every requested target must lie on such a path.
// This never marks reconnaissance satisfied or relaxes zero-lead completion.
func prescanLeadSourceRead(cfg RunConfig, recon *ReconState, state *PlannerState, observed ObservationSet, payload OpenAuditLeadPayload) (bool, error) {
	if cfg.PreScannedTaint == nil || cfg.PreScannedTaint.FactRef == "" {
		return false, nil
	}
	context, fact, err := validatePreScannedTaint(cfg)
	if err != nil {
		return false, err
	}
	if fact == nil {
		return false, nil
	}
	cited := false
	for _, ref := range payload.ReasonFactRefs {
		if ref == context.FactRef || ref == fact.FactID {
			cited = true
		}
	}
	if !cited {
		return false, nil
	}
	if recon.AllowLead() {
		allSeen := true
		for _, target := range payload.TargetSymbolIDs {
			allSeen = allSeen && recon.SawSymbol(target)
		}
		if allSeen {
			return false, nil
		}
	}
	if state == nil || !observed.Observed(context.FactRef) {
		return false, fmt.Errorf("prescan lead requires a fact presented in this sample and actual prior source reads")
	}
	windows := observedSourceWindows(state, observed, observationlimits.MaxBytes)
	read := func(location artifacts.ToolLocation) bool {
		for _, window := range windows {
			if window.Path == location.Path && location.StartLine >= window.Start && location.StartLine <= window.End {
				return true
			}
		}
		return false
	}
	for _, target := range payload.TargetSymbolIDs {
		path, symbol := splitPrescanTarget(string(target))
		if symbol == "" && recon.Mode != ReconModeTreeOnly {
			return false, fmt.Errorf("prescan lead target must name an observed function as path::symbol or a canonical symbol ID")
		}
		matched := false
		for _, witness := range fact.Paths {
			if len(witness) == 0 || !read(witness[0].Location) || !read(witness[len(witness)-1].Location) {
				continue
			}
			for _, node := range witness {
				if node.Location.Path == path && (symbol == "" || prescanSymbolName(node.Location.Symbol) == symbol) && read(node.Location) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false, fmt.Errorf("prescan lead target %q requires previously presented entry and sink source and must belong to that witness path", target)
		}
	}
	return len(payload.TargetSymbolIDs) > 0, nil
}

func splitPrescanTarget(target string) (path, symbol string) {
	parts := strings.SplitN(target, ":", 4)
	if len(parts) == 4 {
		if line, err := strconv.Atoi(parts[2]); err == nil && line > 0 {
			return parts[1], prescanSymbolName(parts[3])
		}
	}
	if path, symbol, ok := strings.Cut(target, "::"); ok {
		return path, prescanSymbolName(symbol)
	}
	return target, ""
}

// Strip a SARIF signature, retaining namespace/class qualification. Dropping
// qualification would incorrectly merge different functions with one name.
func prescanSymbolName(symbol string) string {
	symbol = strings.TrimSpace(symbol)
	if at := strings.IndexByte(symbol, '('); at >= 0 {
		symbol = symbol[:at]
	}
	return strings.TrimPrefix(strings.TrimSpace(symbol), "::")
}
