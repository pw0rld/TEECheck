package contracts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

func ResolveEvidence(r artifacts.ContractEvidenceRef, ctx BindingContext) (artifacts.ContractEvidenceRef, error) {
	switch r.Kind {
	case "source":
		full, err := resolvePath(ctx.RepoRoot, r.Path)
		if err != nil {
			return r, err
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return r, err
		}
		span, err := sourceSpan(data, r.StartLine, r.EndLine)
		if err != nil {
			return r, err
		}
		hash := contentHash(span)
		if r.ContentSHA256 != "" && r.ContentSHA256 != hash {
			return r, fmt.Errorf("source evidence hash mismatch")
		}
		r.ContentSHA256 = hash
		return r, nil
	case "observation":
		if !strings.HasPrefix(r.Ref, "obs:") {
			return r, fmt.Errorf("invalid observation reference")
		}
		if ctx.RunDir == "" {
			return r, fmt.Errorf("observation has no run context")
		}
		f, err := os.Open(runfs.RoundsLogPath(ctx.RunDir))
		if err != nil {
			return r, err
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 16<<20)
		for scan.Scan() {
			var round artifacts.RoundRecord
			if err := json.Unmarshal(scan.Bytes(), &round); err != nil {
				return r, err
			}
			for _, o := range round.Observations {
				if o.Ref == r.Ref {
					if !o.OK {
						return r, fmt.Errorf("observation was not successful")
					}
					return r, nil
				}
			}
		}
		if err := scan.Err(); err != nil {
			return r, err
		}
		return r, fmt.Errorf("observation was not recorded in this run")
	case "tool_fact":
		if _, err := readToolFact(r.Ref, ctx); err != nil {
			return r, err
		}
		full, err := toolFactPath(r.Ref, ctx)
		if err != nil {
			return r, err
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return r, err
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if r.ContentSHA256 != "" && r.ContentSHA256 != digest {
			return r, fmt.Errorf("ToolFact content hash mismatch")
		}
		r.ContentSHA256 = digest
		return r, nil
	default:
		return r, fmt.Errorf("unsupported evidence kind %q", r.Kind)
	}
}

func readToolFact(ref string, ctx BindingContext) (artifacts.ToolFact, error) {
	var fact artifacts.ToolFact
	if strings.HasPrefix(ref, "obs:") {
		return fact, fmt.Errorf("observation reference is not a ToolFact file")
	}
	if ctx.RunDir == "" {
		return fact, fmt.Errorf("ToolFact requires run context")
	}
	full, err := toolFactPath(ref, ctx)
	if err != nil {
		return fact, err
	}
	body, err := os.ReadFile(full)
	if err != nil {
		return fact, err
	}
	if err = json.Unmarshal(body, &fact); err != nil {
		return fact, err
	}
	if err = schema.Validate(schema.TrustIRToolV1, body); err != nil {
		return fact, err
	}
	if err = artifacts.ValidateToolFactContent(fact); err != nil {
		return fact, err
	}
	if artifacts.IsTaintOperation(fact.Operation) && (fact.Status != "success" || fact.Scope == nil) {
		return fact, fmt.Errorf("taint evidence must name a successful scope-bound ToolFact")
	}
	if fact.Scope != nil {
		if err = sameScope(*fact.Scope, ctx.Scope); err != nil {
			return fact, err
		}
	}
	if ctx.Scope.Commit != "" && fact.RepoCommit != ctx.Scope.Commit {
		return fact, fmt.Errorf("ToolFact commit mismatch")
	}
	return fact, nil
}

// LoadToolFact reads only a schema-valid, scope-consistent immutable fact from
// this run. Reviews can include its evidence without trusting model text.
func LoadToolFact(ref string, ctx BindingContext) (artifacts.ToolFact, error) {
	return readToolFact(ref, ctx)
}

// ValidateAssessment checks the one-contract identity and source witnesses.
// It deliberately does not require a complete attack chain for local violation.
func ValidateAssessment(a artifacts.InvariantAssessment, c artifacts.CaseInvariantV2, ctx BindingContext) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if err = schema.Validate(schema.InvariantAssessmentV1, body); err != nil {
		return err
	}
	if a.Scope.RepoURL != c.Scope.RepoURL {
		return fmt.Errorf("assessment repository mismatch")
	}
	if a.Scope.Commit == "" || a.Scope.Commit != c.Scope.Commit {
		return fmt.Errorf("assessment requires exact contract revision")
	}
	if a.InvariantID != c.InvariantID || a.DefinitionHash != c.DefinitionHash {
		return fmt.Errorf("assessment contract identity mismatch")
	}
	if err = sameScope(a.Scope, c.Scope); err != nil {
		return err
	}
	if err = sameScope(a.Scope, ctx.Scope); err != nil {
		return err
	}
	for _, r := range a.EvidenceRefs {
		if _, err := ResolveEvidence(r, ctx); err != nil {
			return err
		}
	}
	for _, w := range a.Witness {
		if w.ContentSHA256 == "" || w.StartLine < 1 || w.EndLine < w.StartLine {
			return fmt.Errorf("assessment witness is not anchored")
		}
		if _, err := BindSubject(w, ctx); err != nil {
			return err
		}
		allowed := false
		for _, s := range c.Subjects {
			if s.Path == w.Path && s.Symbol == w.Symbol {
				allowed = true
			}
		}
		for _, r := range c.EvidenceRefs {
			if r.Kind == "source" && r.Path == w.Path && r.Symbol != "" && r.Symbol == w.Symbol && w.StartLine >= r.StartLine && w.EndLine <= r.EndLine {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("witness belongs to another contract")
		}
	}
	if a.Assessment == "unresolved" {
		return nil
	}
	if err := Validate(c, ctx); err != nil {
		return err
	}
	if c.Grounding != "source_bound" {
		return fmt.Errorf("positive assessment requires bound contract")
	}
	if len(a.Witness) == 0 || len(a.EvidenceRefs) == 0 {
		return fmt.Errorf("registered assessment requires bound source witnesses and evidence")
	}
	if (!a.SourceCorroborated || !a.PreconditionsSatisfied || len(a.Contradictions) > 0) && len(a.MissingEvidence) == 0 {
		return fmt.Errorf("unresolved source review or preconditions must be recorded as missing evidence")
	}
	if a.AttackChainComplete && (!a.SourceCorroborated || !a.PreconditionsSatisfied || len(a.Contradictions) > 0 || len(a.MissingEvidence) > 0) {
		return fmt.Errorf("complete attack chain cannot retain unresolved prerequisites")
	}
	if a.VerificationBasis != "registered_query" {
		return fmt.Errorf("positive assessment requires registered-query proof")
	}
	foundQuery := false
	for _, q := range c.VerificationQueries {
		if q.Operation == a.QueryOperation {
			foundQuery = true
		}
	}
	if a.QueryOperation == "" || !foundQuery {
		return fmt.Errorf("assessment query is not in the contract")
	}
	foundFact := false
	for _, r := range a.EvidenceRefs {
		if r.Kind == "tool_fact" {
			f, err := readToolFact(r.Ref, ctx)
			if err == nil && f.Status == "success" && f.Operation == a.QueryOperation {
				var result struct {
					Assessment   string `json:"assessment"`
					ContractHash string `json:"contract_hash"`
					ReasonCode   string `json:"reason_code"`
				}
				if json.Unmarshal(f.Result, &result) == nil && result.Assessment == a.Assessment && result.ContractHash == a.DefinitionHash && result.ReasonCode == a.ReasonCode {
					foundFact = true
				}
			}
		}
	}
	if !foundFact {
		return fmt.Errorf("positive assessment has no successful matching ToolFact")
	}
	return nil
}

func toolFactPath(ref string, ctx BindingContext) (string, error) {
	if ctx.RunDir == "" {
		return "", fmt.Errorf("ToolFact requires run context")
	}
	root, err := filepath.Abs(ctx.RunDir)
	if err != nil {
		return "", err
	}
	rel := ref
	candidate, err := filepath.Abs(ref)
	if err != nil {
		return "", err
	}
	relative, relErr := filepath.Rel(root, candidate)
	// Producers may return a run-relative path or a cwd-relative run path.
	// Both must resolve inside the same run; absolute outside paths fail.
	if filepath.IsAbs(ref) || (relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		if relErr != nil {
			return "", relErr
		}
		rel = relative
	}
	return resolvePath(root, rel)
}
