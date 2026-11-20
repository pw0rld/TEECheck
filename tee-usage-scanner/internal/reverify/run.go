// Package reverify runs a frozen logical contract against another local source
// revision. It never starts a Planner or writes into the audit knowledge loop.
package reverify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

type AssessmentFunc func(context.Context, config.Config, artifacts.CaseInvariantV2, contracts.BindingContext) (artifacts.InvariantAssessment, error)

func Run(cfg config.Config) (string, error) {
	return RunWithAssessment(context.Background(), cfg, func(ctx context.Context, cfg config.Config, c artifacts.CaseInvariantV2, binding contracts.BindingContext) (artifacts.InvariantAssessment, error) {
		engine := codeql.New()
		db := codedb.New(engine, nil)
		runner := verifier.NewContractQueryRunner(engine, db, cfg.RunDir)
		return verifier.Reverify(ctx, cfg, c, binding, runner)
	})
}

func RunWithAssessment(ctx context.Context, cfg config.Config, assess AssessmentFunc) (string, error) {
	if cfg.ContractPath == "" || cfg.LocalPath == "" {
		return "", fmt.Errorf("contract and local repo root are required")
	}
	if repofetch.IsURL(cfg.LocalPath) {
		return "", fmt.Errorf("verify-contract requires local source; it never invokes the Planner or clones its input")
	}
	input, err := os.ReadFile(cfg.ContractPath)
	if err != nil {
		return "", err
	}
	if err = schema.Validate(schema.CaseInvariantV2, input); err != nil {
		return "", fmt.Errorf("input is not a standalone CaseInvariantV2: %w", err)
	}
	var original artifacts.CaseInvariantV2
	if err = json.Unmarshal(input, &original); err != nil {
		return "", err
	}
	if original.DefinitionHash != contracts.DefinitionHash(original) {
		return "", fmt.Errorf("input logical definition hash mismatch")
	}
	source, err := repofetch.Fetch(cfg.LocalPath)
	if err != nil {
		return "", err
	}
	sourceMode, err := resolveSourceIdentity(ctx, source.LocalPath, &cfg)
	if err != nil {
		return "", err
	}
	if cfg.RepoURL == "" {
		cfg.RepoURL = source.RepoURL
	}
	if cfg.RepoURL == "" {
		cfg.RepoURL = source.LocalPath
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "contract-rechecks"
	}
	base, err := safeOutputRoot(cfg.OutputDir, cfg.ContractPath)
	if err != nil {
		return "", err
	}
	if within(source.LocalPath, base) {
		return "", fmt.Errorf("contract recheck output must be outside the source tree")
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	out, err := os.MkdirTemp(base, "verify-")
	if err != nil {
		return "", err
	}
	cfg.RunDir = out
	cfg.LocalPath = source.LocalPath
	cfg.Command = "verify-contract"
	binding := contracts.BindingContext{RepoRoot: source.LocalPath, RunDir: out, Scope: runfs.BuildScope(cfg.RepoURL, cfg.Commit, source.LocalPath)}
	logical := contracts.LogicalDefinition(original)
	contract, diagnostics, err := contracts.Bind(logical, binding)
	if err != nil {
		return out, err
	}
	if err = runfs.WriteJSON(filepath.Join(out, "logical_contract.json"), logical); err != nil {
		return out, err
	}
	if err = runfs.WriteJSON(filepath.Join(out, "contract.json"), contract); err != nil {
		return out, err
	}
	manifest := map[string]any{"schema_version": "teecheck.contract_recheck.v1", "mode": "contract_recheck", "source_scope_mode": sourceMode, "scope": binding.Scope, "invariant_id": contract.InvariantID, "definition_hash": contract.DefinitionHash, "binding_diagnostics": diagnostics}
	roles, roleErr := cfg.ResolveRoleConfigs()
	if roleErr != nil {
		return out, roleErr
	}
	role := roles["verifier"]
	manifest["verifier_configuration"] = map[string]any{
		"provider": role.LLMProvider, "model": role.LLMModel, "base_url": config.RedactedEndpoint(role.LLMBaseURL),
		"transport": role.LLMTransport, "reasoning_effort": role.LLMReasoningEffort, "timeout_seconds": role.LLMTimeoutSec,
		"max_output_tokens": role.LLMMaxTokens, "temperature": role.LLMTemp, "api_key_present": role.LLMAPIKey != "",
	}
	if err = runfs.WriteJSON(filepath.Join(out, "manifest.json"), manifest); err != nil {
		return out, err
	}
	var assessment artifacts.InvariantAssessment
	if contract.Grounding != "source_bound" {
		assessment = artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: contract.InvariantID, DefinitionHash: contract.DefinitionHash, Scope: contract.Scope, Assessment: "unresolved", ReasonCode: "binding_unresolved", Reason: "The frozen logical contract could not be uniquely bound to this source revision.", VerificationBasis: "unavailable"}
	} else {
		if assess == nil {
			return out, fmt.Errorf("assessment callback is required")
		}
		assessment, err = assess(ctx, cfg, contract, binding)
		if err != nil {
			return out, err
		}
	}
	if err = contracts.ValidateAssessment(assessment, contract, binding); err != nil {
		return out, fmt.Errorf("invalid contract assessment: %w", err)
	}
	if err = runfs.WriteJSON(filepath.Join(out, "assessment.json"), assessment); err != nil {
		return out, err
	}
	return out, nil
}

func safeOutputRoot(requested, input string) (string, error) {
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	// Resolve existing ancestors before checking, so a symlink cannot redirect
	// a seemingly independent output directory into a protected location.
	tail := []string{}
	existing := abs
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		tail = append(tail, filepath.Base(existing))
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	for i := len(tail) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, tail[i])
	}
	for _, part := range strings.Split(filepath.ToSlash(resolved), "/") {
		if part == "knowledge" || part == "feedback" || part == "runs" {
			return "", fmt.Errorf("contract rechecks cannot write into %s directories", part)
		}
	}
	inputAbs, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	inputAbs, err = filepath.EvalSymlinks(inputAbs)
	if err != nil {
		return "", err
	}
	for dir := resolved; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "00_manifest.json")); err == nil {
			return "", fmt.Errorf("contract rechecks cannot write inside any existing scan run")
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	for dir := filepath.Dir(inputAbs); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "00_manifest.json")); err == nil {
			if within(dir, resolved) {
				return "", fmt.Errorf("contract rechecks cannot write into the original scan run")
			}
			break
		}
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
	return resolved, nil
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
